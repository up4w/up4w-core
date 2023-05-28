#pragma once
#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_packet.h"
#include "mlt_internal_util.h"


namespace upw
{

class MLT_IncomingFile
{
public:
	enum Error {
		E_NoError,						// everything ok
		E_NoWriter,						// no writer given to constructor
		E_CorruptedControlData,			// the control block data returned from writer is corrupted
		E_WriteFileFailed,				// writer encountered error when flushing buffer
		E_WriteControlDataFailed,		// writer encountered error when writing control block data
	};

private:
	const MLT_FileHash					_fileHash;								// hash of the file
	const uint64_t						_fileSize = 0;							// size of file
	MLT_IncomingFileWriter				* const _pWriter = nullptr;				// interface provided by user to write file and control data out
	const uint32_t						_priority = 0;							// priority of the task
	const uint32_t						_fileId = 0;							// the task id of this file download

	uint32_t							_numBlocks = 0;							// number of blocks in this file, each block has size of MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize
	uint32_t							_numSlices = 0;							// number of slices in this file, each slice has size of MLT_Packet::PKT_FILE_SLICE::fileSliceSize
	bool								_bCurBlockRequestSent = false;			// Whether FileRequestBlock packet for the current block has already been sent

	std::vector<uint8_t>				_buffer;								// memory buffer for received data

	uint64_t							_lastBufferFlushTS = 0;					// when the buffer was last flushed
	uint64_t							_flushBufferIntervalInMS = 2000;		// minimal interval between buffer flushes

	Error								_lastError;								// the last error encountered

	bool								_bFileAcknowledgeSent = false;			// whether FileAcknowledge packet has been sent

#pragma pack(push, 1)
	struct ControlBlock
	{
		uint8_t		version = 1;												// version of the control block
		uint32_t	curBlockIdx = 0;											// index of the current block
		uint32_t	nextWriteSliceIdxInBlock = 0;								// the first slice in the current block to write out in next flush (i.e. all slices before that have already been flushed)
	};
#pragma pack(pop)

	ControlBlock						_controlBlock;							// ...
	uint8_t								_curBlockSliceMask[MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock / 8];		// bitmask of all slices in the current block, whether each slice has been received
	uint32_t							_numRemainingSlicesInCurrentBlock = 0;	// number of slices in current block that haven't been received
	uint64_t							_downloadedSize = 0;					// how many bytes in this file (across all blocks) have been received
	MLT_ValueHistory<60>				_speedHistory;							// record of download speed in the last period of time

	static uint32_t _GetBlockSize(uint32_t blockIdx, uint64_t fileSize)
	{
		return uint32_t(std::min(fileSize - uint64_t(blockIdx) * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize, uint64_t(MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize)));
	}
	static uint32_t _GetNumSlicesInBlock(uint32_t blockIdx, uint32_t totalNumSlices)
	{
		return uint32_t(std::min(totalNumSlices - blockIdx * MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock, uint32_t(MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock)));
	}
	static uint32_t _GetSliceLen(uint32_t sliceIdx, uint64_t fileSize)
	{
		return uint32_t(std::min(fileSize - uint64_t(sliceIdx) * MLT_Packet::PKT_FILE_SLICE::fileSliceSize, uint64_t(MLT_Packet::PKT_FILE_SLICE::fileSliceSize)));
	}

	bool _FlushBuffer(bool bForce);

public:
	MLT_IncomingFile(const MLT_FileHash &fileHash, uint64_t fileSize, MLT_IncomingFileWriter *pWriter, uint32_t priority, uint32_t fileId);
	~MLT_IncomingFile();
	bool PullBlockRequest(uint32_t &outBlockIdx, uint8_t *&outSliceMask, uint16_t &outSliceMaskLen);
	void OnBlockRequestLost()
	{
		_bCurBlockRequestSent = false;
	}
	void OnBlockRequestAcked()
	{
		// nothing to do here
	}
	void FinalizeWriter()
	{
		_pWriter->FinalizeWrite();
	}

	bool OnRecvFileSlice(uint32_t sliceIdx, const uint8_t *pSlice, uint16_t sliceLen);		// returns false if the slice is not what we want, or a write to disk failed. Check the latter case with HasError()

	bool IsDone() const { return _controlBlock.curBlockIdx == _numBlocks - 1 && _numRemainingSlicesInCurrentBlock == 0; }

	bool PullFileAcknowledge()
	{
		if(IsDone() && !_bFileAcknowledgeSent)
		{
			_bFileAcknowledgeSent = true;
			return true;
		}

		return false;
	}

	void OnFileAcknowledgeLost()
	{
		_bFileAcknowledgeSent = false;
	}

	void OnFileAcknowledgeAcked()
	{
		// No need to do anything
	}


	Error GetLastError() const { return _lastError; }

	uint32_t GetId()  const { return _fileId; }
	
	const MLT_FileHash& GetFileHash() const { return _fileHash; }
	uint64_t GetFileSize() const { return _fileSize; }
	uint32_t GetFilePriority() const { return _priority; }
	uint64_t GetDownloadedSize() const;
	uint64_t GetDownloadSpeed() const;
	uint32_t GetCurBlockIdx() const { return _controlBlock.curBlockIdx; }
	uint32_t GetNumRemainingSlicesInCurBlock() const { return _numRemainingSlicesInCurrentBlock; }
	uint32_t GetFirstRemainingSliceInCurBlcok() const;
	bool GetCurBlockRequestSent() const { return _bCurBlockRequestSent; }

	void OnTick()
	{
		_FlushBuffer(false);
	}

	void OnDestinationSessionChange()
	{
		_bCurBlockRequestSent = false;
	}

	static int64_t GetControlBlockNumDownloadedBytes(const uint8_t *pCB, uint32_t cbSize, uint64_t totalSize);
};

class MLT_OutgoingFile
{
	const MLT_FileHash					_fileHash;
	const uint64_t						_fileSize = 0;
	MLT_OutgoingFileReader				* const _pReader = nullptr;
	const uint32_t						_priority = 0;
	const uint32_t						_fileId = 0;

	uint32_t							_numBlocks = 0;
	uint32_t							_numSlices = 0;

	uint32_t							_requestedBlockIndex = 0xffffffff;
	std::vector<uint8_t>				_buffer;
	std::set<uint32_t>					_toSendSlices;
	std::set<uint32_t>					_pendingAckSlices;

	// debug
	uint32_t							_numPullSlice = 0;
	uint32_t							_numAck = 0;
	uint32_t							_numLost = 0;

public:
	MLT_OutgoingFile(const MLT_FileHash &fileHash, uint64_t fileSize, MLT_OutgoingFileReader *pReader, uint32_t priority, uint32_t fileId);
	~MLT_OutgoingFile();
	bool RequestBlock(uint32_t blockIdx, const uint8_t *sliceMask, uint16_t sliceMaskLen);
	void OnFileSliceAcked(uint32_t customData);
	void OnFileSliceLost(uint32_t customData);
	bool PullNextSlice(const uint8_t *&outData, uint16_t &outDataLen, uint32_t &outSliceIdx);
	uint32_t GetId() { return _fileId; }
	uint64_t GetFileSize() const { return _fileSize; }
	uint32_t GetRequestedBlockIndex() const { return _requestedBlockIndex; }
	uint32_t GetNumRemainingSlices() const { return uint32_t(_toSendSlices.size()); }
	uint32_t GetNumPendingAckSlices() const { return uint32_t(_pendingAckSlices.size()); }
	uint32_t GetNumPullSlice() const { return _numPullSlice; }
	uint32_t GetNumAcks() const { return _numAck; }
	uint32_t GetNumLosts() const { return _numLost; }
	MLT_OutgoingFileReader* GetFileReader() { return _pReader; }
};

} // namespace upw