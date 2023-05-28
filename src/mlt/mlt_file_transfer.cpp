#include "../netsvc_core.h"
#include "mlt_file_transfer.h"

namespace upw
{


MLT_IncomingFile::MLT_IncomingFile(const MLT_FileHash &fileHash, uint64_t fileSize, MLT_IncomingFileWriter *pWriter, uint32_t priority, uint32_t fileId)
	: _fileHash(fileHash), _fileSize(fileSize), _pWriter(pWriter), _priority(priority), _fileId(fileId)
{
	_numBlocks = uint32_t((_fileSize + MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize - 1) / MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize);
	_numSlices = uint32_t((_fileSize + MLT_Packet::PKT_FILE_SLICE::fileSliceSize - 1) / MLT_Packet::PKT_FILE_SLICE::fileSliceSize);
	_downloadedSize = 0;
	_lastError = E_NoError;

	// always initialize control data to default values
	_controlBlock.curBlockIdx = 0;
	_controlBlock.nextWriteSliceIdxInBlock = 0;
	memset(_curBlockSliceMask, 0, sizeof(_curBlockSliceMask));
	_numRemainingSlicesInCurrentBlock = _GetNumSlicesInBlock(_controlBlock.curBlockIdx, _numSlices);

	const uint8_t *pControlData = nullptr;
	if(pWriter)
	{
		uint32_t controlDataLen = 0;
		if(!pWriter->GetControlData(&pControlData, &controlDataLen))
		{
			_LOG("MLT_IncomingFile::MLT_IncomingFile(): GetControlData() failed.");
			_lastError = E_CorruptedControlData;
			return;
		}
		if(pControlData)
		{
			if(controlDataLen != sizeof(ControlBlock) || (*(ControlBlock*)pControlData).version != _controlBlock.version || (*(ControlBlock*)pControlData).curBlockIdx >= _numBlocks)
			{
				_LOG("MLT_IncomingFile::MLT_IncomingFile(): control data has invalid format / data.");
				_lastError = E_CorruptedControlData;
				return;
			}

			memcpy(&_controlBlock, pControlData, controlDataLen);
			_downloadedSize = uint64_t(_controlBlock.curBlockIdx) * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize;
			uint32_t sliceIdxBase = _controlBlock.curBlockIdx * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock;
			_numRemainingSlicesInCurrentBlock = 0;
			uint32_t numSlicesInCurBlock = _GetNumSlicesInBlock(_controlBlock.curBlockIdx, _numSlices);
			memset(_curBlockSliceMask, 0, sizeof(_curBlockSliceMask));
			for(uint32_t i = 0; i < _controlBlock.nextWriteSliceIdxInBlock; i++)
			{
				_downloadedSize += _GetSliceLen(sliceIdxBase + i, _fileSize);
				_curBlockSliceMask[i / 8] |= 1 << (i % 8);
			}
			_numRemainingSlicesInCurrentBlock = numSlicesInCurBlock - _controlBlock.nextWriteSliceIdxInBlock;
			if(_numRemainingSlicesInCurrentBlock == 0 && _controlBlock.curBlockIdx + 1 < _numBlocks)
			{
				_controlBlock.curBlockIdx++;
				_controlBlock.nextWriteSliceIdxInBlock = 0;
				memset(_curBlockSliceMask, 0, sizeof(_curBlockSliceMask));
				_numRemainingSlicesInCurrentBlock = _GetNumSlicesInBlock(_controlBlock.curBlockIdx, _numSlices);
				if(!_pWriter->SetControlData((uint8_t*)&_controlBlock, sizeof(_controlBlock)))
				{
					_LOG("MLT_IncomingFile::MLT_IncomingFile(): SetControlData() fail case 1.");
					_lastError = E_WriteControlDataFailed;
					return;
				}
			}
		}
	}
	else
	{
		_LOG("MLT_IncomingFile::MLT_IncomingFile(): No writer.");
		_lastError = E_NoWriter;
		return;
	}

	if(!pControlData)
	{
		_controlBlock.curBlockIdx = 0;
		_controlBlock.nextWriteSliceIdxInBlock = 0;
		memset(_curBlockSliceMask, 0, sizeof(_curBlockSliceMask));
		_numRemainingSlicesInCurrentBlock = _GetNumSlicesInBlock(_controlBlock.curBlockIdx, _numSlices);
		if(pWriter)
		{
			if(!pWriter->SetControlData((uint8_t*)&_controlBlock, sizeof(_controlBlock)))
			{
				_LOG("MLT_IncomingFile::MLT_IncomingFile(): SetControlData() failed case 2.");
				_lastError = E_WriteControlDataFailed;
				return;
			}
		}
	}

	_lastBufferFlushTS = uint64_t(os::Timestamp::Get());
}

MLT_IncomingFile::~MLT_IncomingFile()
{
	_FlushBuffer(true);

	if(_pWriter)
		_pWriter->Release();
}

bool MLT_IncomingFile::_FlushBuffer(bool bForce)
{
	uint64_t curTime = uint64_t(os::Timestamp::Get());

	if(!bForce && curTime < _lastBufferFlushTS + _flushBufferIntervalInMS)
		return true;
	if(_buffer.size() == 0)
		return true;

	uint32_t writeSliceIdxEnd = _controlBlock.nextWriteSliceIdxInBlock;
	uint32_t numSlicesInCurBlock = _GetNumSlicesInBlock(_controlBlock.curBlockIdx, _numSlices);
	{
		while(writeSliceIdxEnd < numSlicesInCurBlock && (_curBlockSliceMask[writeSliceIdxEnd / 8] & (1 << (writeSliceIdxEnd % 8))) != 0)
			writeSliceIdxEnd++;
	}
	if(writeSliceIdxEnd > _controlBlock.nextWriteSliceIdxInBlock)
	{
		if(_pWriter)
		{
			uint32_t writeBeginOffsetInBlock = _controlBlock.nextWriteSliceIdxInBlock * MLT_Packet::PKT_FILE_SLICE::fileSliceSize;
			uint32_t writeLen = (writeSliceIdxEnd - _controlBlock.nextWriteSliceIdxInBlock - 1) * MLT_Packet::PKT_FILE_SLICE::fileSliceSize;
			writeLen += _GetSliceLen(writeSliceIdxEnd - 1 + _controlBlock.curBlockIdx * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock, _fileSize);

			if(!_pWriter->Write(uint64_t(_controlBlock.curBlockIdx) * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize + writeBeginOffsetInBlock, &_buffer[writeBeginOffsetInBlock], writeLen))
			{
				_lastError = E_WriteFileFailed;
				return false;
			}
		}

		_controlBlock.nextWriteSliceIdxInBlock = writeSliceIdxEnd;

		if(_pWriter)
		{
			if(!_pWriter->SetControlData((uint8_t*)&_controlBlock, sizeof(_controlBlock)))
			{
				_lastError = E_WriteControlDataFailed;
				return false;
			}
		}

		_lastBufferFlushTS = curTime;
	}

	return true;
}

bool MLT_IncomingFile::PullBlockRequest(uint32_t &outBlockIdx, uint8_t *&outSliceMask, uint16_t &outSliceMaskLen)
{
	if(IsDone())
		return false;
	if(_bCurBlockRequestSent)
		return false;

	outBlockIdx = _controlBlock.curBlockIdx;
	outSliceMask = _curBlockSliceMask;
	outSliceMaskLen = sizeof(_curBlockSliceMask);
	_bCurBlockRequestSent = true;
	return true;
}

bool MLT_IncomingFile::OnRecvFileSlice(uint32_t sliceIdx, const uint8_t *pSlice, uint16_t sliceLen)
{
	if(sliceIdx / MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock != _controlBlock.curBlockIdx || sliceIdx >= _numSlices)
	{
		_LOG("MLT_IncomingFile::OnRecvFileSlice(): sliceIdx " << sliceIdx << " not a valid value in current block.");
		return false;
	}

	if(_GetSliceLen(sliceIdx, _fileSize) != sliceLen)
	{
		_LOG("MLT_IncomingFile::OnRecvFileSlice(): sliceLen " << sliceLen << "incorrect.");
		return false;
	}

	uint32_t sliceIdxInBlock = sliceIdx % MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock;
	if(_curBlockSliceMask[sliceIdxInBlock / 8] & (1 << (sliceIdxInBlock % 8)))
	{
		_LOG("MLT_IncomingFile::OnRecvFileSlice(): slice " << sliceIdx << " already received.");
		return false;
	}

	if(_numRemainingSlicesInCurrentBlock == 0)
	{
		_LOG_ERROR("MLT_IncomingFile::OnRecvFileSlice() detects _numRemainingSlicesInCurrentBlock == 0 when getting a new file slice, BUG!");
		return false;
	}

	uint32_t curBlockSize = _GetBlockSize(_controlBlock.curBlockIdx, _fileSize);
	if(_buffer.size() != curBlockSize)
	{
		_buffer.resize(curBlockSize);
		for(uint32_t i = 0; i < curBlockSize; i++)
			_buffer[i] = 255 - (i & 0xff);
	}

	uint32_t byteOffsetInBlock = sliceIdxInBlock * MLT_Packet::PKT_FILE_SLICE::fileSliceSize;

	memcpy(&_buffer[byteOffsetInBlock], pSlice, sliceLen);
	_curBlockSliceMask[sliceIdxInBlock / 8] |= (1 << (sliceIdxInBlock % 8));
	_numRemainingSlicesInCurrentBlock--;

	_downloadedSize += sliceLen;
	_speedHistory.AddData(uint64_t(os::Timestamp::Get()) / 1000, sliceLen);

	if(_numRemainingSlicesInCurrentBlock == 0)
	{
		if(!_FlushBuffer(true))
		{
			return false;
		}
		if(_controlBlock.curBlockIdx + 1 < _numBlocks)
		{
			_controlBlock.curBlockIdx++;
			_controlBlock.nextWriteSliceIdxInBlock = 0;
			memset(_curBlockSliceMask, 0, sizeof(_curBlockSliceMask));
			_numRemainingSlicesInCurrentBlock = _GetNumSlicesInBlock(_controlBlock.curBlockIdx, _numSlices);
			_bCurBlockRequestSent = false;
		}
		if(_pWriter)
		{
			if(!_pWriter->SetControlData((uint8_t*)&_controlBlock, sizeof(_controlBlock)))
			{
				_lastError = E_WriteControlDataFailed;
				return false;
			}
		}
	}
	else
	{
		if(!_FlushBuffer(false))
		{
			return false;
		}
	}

	return true;
}

uint64_t MLT_IncomingFile::GetDownloadedSize() const
{
	return _downloadedSize;
}

uint64_t MLT_IncomingFile::GetDownloadSpeed() const
{
	return _speedHistory.GetAvgValue(uint64_t(os::Timestamp::Get()) / 1000, 5);
}

uint32_t MLT_IncomingFile::GetFirstRemainingSliceInCurBlcok() const
{
	if(_numRemainingSlicesInCurrentBlock > 0)
	{
		for(uint32_t i = 0; i < MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock; i++)
			if((_curBlockSliceMask[i / 8] & (1 << (i % 8))) == 0)
				return i;
	}

	return 0xffffffffu;
}

int64_t MLT_IncomingFile::GetControlBlockNumDownloadedBytes(const uint8_t *pCB, uint32_t cbSize, uint64_t totalSize)
{
	if(cbSize != sizeof(ControlBlock))
		return -1;
	const ControlBlock &cb = *(const ControlBlock*)pCB;
	if(cb.version != 1)
		return -1;

	uint32_t numBlocks = uint32_t((totalSize + MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize - 1) / MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize);

	if(cb.curBlockIdx >= numBlocks)
		return -1;
	uint32_t numSlices = uint32_t((totalSize + MLT_Packet::PKT_FILE_SLICE::fileSliceSize - 1) / MLT_Packet::PKT_FILE_SLICE::fileSliceSize);

	uint64_t ret = MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize * uint64_t(cb.curBlockIdx);

	uint32_t numSlicesInCurBlock = _GetNumSlicesInBlock(cb.curBlockIdx, numSlices);
	uint32_t sliceIdxBase = cb.curBlockIdx * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock;
	for(uint32_t i = 0; i < cb.nextWriteSliceIdxInBlock; i++)
		ret += _GetSliceLen(sliceIdxBase + i, totalSize);

	return ret;
}

MLT_OutgoingFile::MLT_OutgoingFile(const MLT_FileHash &fileHash, uint64_t fileSize, MLT_OutgoingFileReader *pReader, uint32_t priority, uint32_t fileId)
	: _fileHash(fileHash), _fileSize(fileSize), _pReader(pReader), _priority(priority), _fileId(fileId)
{
	_numBlocks = (_fileSize + MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize - 1) / MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize;
	_numSlices = (_fileSize + MLT_Packet::PKT_FILE_SLICE::fileSliceSize - 1) / MLT_Packet::PKT_FILE_SLICE::fileSliceSize;
}

MLT_OutgoingFile::~MLT_OutgoingFile()
{
}

bool MLT_OutgoingFile::RequestBlock(uint32_t blockIdx, const uint8_t *sliceMask, uint16_t sliceMaskLen)
{
	if(!_pReader)
		return false;

	if(blockIdx >= _numBlocks)
		return false;

	uint32_t curBlockSize = uint32_t(std::min(_fileSize - uint64_t(blockIdx) * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize, uint64_t(MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize)));
	if(!curBlockSize)
		return false;
	if(sliceMaskLen != MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock / 8)
		return false;

	_buffer.resize(curBlockSize);

	if(_pReader->Read(blockIdx * uint64_t(MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize), curBlockSize, &_buffer[0]) != curBlockSize)
		return false;
	
	uint32_t numSlicesInBlock = uint32_t(std::min(_numSlices - blockIdx * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock, uint32_t(MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock)));
	for(uint16_t i = 0; i < numSlicesInBlock; i++)
	{
		if((sliceMask[i / 8] & (1 << (i % 8))) == 0)
			_toSendSlices.insert(i);
	}

	if(_toSendSlices.size() == 0)
		return false;

	_requestedBlockIndex = blockIdx;

	return true;
}

bool MLT_OutgoingFile::PullNextSlice(const uint8_t *&outData, uint16_t &outDataLen, uint32_t &outSliceIdx)
{
	if(_toSendSlices.size() == 0)
		return false;

	uint32_t sliceIdxBase = _requestedBlockIndex * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock;

	uint32_t sliceIdxInBlock = *_toSendSlices.begin();
	outSliceIdx = sliceIdxBase + sliceIdxInBlock;

	outData = &_buffer[uint64_t(sliceIdxInBlock) * MLT_Packet::PKT_FILE_SLICE::fileSliceSize];
	
	outDataLen = uint16_t(std::min(_fileSize - uint64_t(outSliceIdx) * MLT_Packet::PKT_FILE_SLICE::fileSliceSize, uint64_t(MLT_Packet::PKT_FILE_SLICE::fileSliceSize)));

	_pendingAckSlices.insert(*_toSendSlices.begin());
	_toSendSlices.erase(_toSendSlices.begin());

	_numPullSlice++;

	return true;
}

void MLT_OutgoingFile::OnFileSliceAcked(uint32_t customData)
{
	uint32_t sliceIdxBase = _requestedBlockIndex * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock;
	if(customData < sliceIdxBase)
		return;

	_numAck++;

	customData -= sliceIdxBase;
	_pendingAckSlices.erase(customData);
}

void MLT_OutgoingFile::OnFileSliceLost(uint32_t customData)
{
	uint32_t sliceIdxBase = _requestedBlockIndex * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock;
	if(customData < sliceIdxBase)
		return;

	_numLost++;

	customData -= sliceIdxBase;

	auto itor = _pendingAckSlices.find(customData);
	if(itor != _pendingAckSlices.end())
	{
		_pendingAckSlices.erase(itor);
		_toSendSlices.insert(customData);
	}
}

} // namespace upw
