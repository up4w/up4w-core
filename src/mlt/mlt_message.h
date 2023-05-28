#pragma once
#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_packet.h"


namespace upw
{

class MLT_OutgoingMessage
{
	const uint8_t				*_pData;
	const uint32_t				_dataLen;
	const void					*_pCookie;
	const uint32_t				_priority;
	const uint32_t				_msgId;

	uint32_t					_numSlices = 0;

	std::set<uint32_t>			_pendingAckSlices;
	std::set<uint32_t>			_lostSlices;
	uint32_t					_nextSliceIdx;
	uint32_t					_numAckedSlices;
	uint32_t					_numTotalLostSlices;
	uint32_t					_numTotalSentSlices;
	uint64_t					_AddedTs = 0;

public:
	MLT_OutgoingMessage(const uint8_t *pData, uint32_t dataLen, void *pCookie, uint32_t priority, uint32_t msgId)
		: _pData(pData), _dataLen(dataLen), _pCookie(pCookie), _priority(priority), _msgId(msgId)
	{
		_numSlices = dataLen / MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize + (dataLen % MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize ? 1 : 0);
		_AddedTs = uint64_t(os::Timestamp::Get());
		ResetProgress();
	}

	void OnSliceLost(uint32_t customData)
	{
		auto itor = _pendingAckSlices.find(customData);
		if(itor != _pendingAckSlices.end())
		{
			_pendingAckSlices.erase(itor);
			_lostSlices.insert(customData);
			_numTotalLostSlices++;
		}
	}

	void OnSliceAcked(uint32_t customData)
	{
		auto itor = _pendingAckSlices.find(customData);
		if(itor != _pendingAckSlices.end())
		{
			_pendingAckSlices.erase(itor);
			_numAckedSlices++;
		}
	}

	bool PullNextSlice(const uint8_t *&outData, uint16_t &outDataLen, uint32_t &outSliceIdx)
	{
		uint32_t sliceIdx = _numSlices;
		if(_lostSlices.size())
		{
			sliceIdx = *_lostSlices.begin();
			_lostSlices.erase(_lostSlices.begin());
		}
		else if(_nextSliceIdx < _numSlices)
		{
			sliceIdx = _nextSliceIdx++;
		}

		if(sliceIdx == _numSlices)
			return false;

		outData = _pData + sliceIdx * MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize;
		outDataLen = uint16_t(std::min(_dataLen - sliceIdx * MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize, MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize));
		outSliceIdx = sliceIdx;
		_pendingAckSlices.insert(sliceIdx);

		_numTotalSentSlices++;

		return true;
	}

	bool IsDone() const 
	{
		return _numAckedSlices == _numSlices;
	}

	uint32_t GetId() const
	{
		return _msgId;
	}

	uint32_t GetTotalLen() const
	{
		return _dataLen;
	}

	uint32_t GetTotalSent() const
	{
		return _numTotalSentSlices;
	}

	uint32_t GetTotalLost() const
	{
		return _numTotalLostSlices;
	}

	uint32_t GetTotalSlices() const
	{
		return _numSlices;
	}

	uint32_t GetPending() const
	{
		return uint32_t(_pendingAckSlices.size());
	}

	const void* GetCookie() const
	{
		return _pCookie;
	}

	uint64_t GetAddedTs() const
	{
		return _AddedTs;
	}

	void ResetProgress()
	{
		_nextSliceIdx = 0;
		_numAckedSlices = 0;
		_numTotalLostSlices = 0;
		_numTotalSentSlices = 0;
		_lostSlices.clear();
		_pendingAckSlices.clear();
	}
};

class MLT_IncomingMessage
{
	const uint32_t			_msgId;										// id of the message
	const uint32_t			_dataLen;									// length of the message
	std::vector<bool>		_vbSliceReceived;							// whether each slice of the message has been received
	std::vector<uint8_t>	_data;										// buffer for received message data
	uint32_t				_numUniqueSliceReceived = 0;				// number of slices received, not counting duplicates
	uint32_t				_numDuplicatedSliceReceived = 0;			// how many duplicated slices have been received, this could be caused by the sender not receiving our ACKs to slice packets
	uint64_t				_lastIncomingDataTime = 0;					// when the last time we received valid new slice data
	bool					_bMessageAcknowledgeSent = false;			// whether the MessageAcknowledge packet is already sent and is waiting for ack from other side
public:
	MLT_IncomingMessage(uint32_t msgId, uint32_t dataLen)
		: _msgId(msgId), _dataLen(dataLen)
	{
		uint32_t numSlices = dataLen / MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize + (dataLen % MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize ? 1 : 0);
		_vbSliceReceived.resize(numSlices, false);
		_data.resize(dataLen);
		_lastIncomingDataTime = uint64_t(os::Timestamp::Get());
	}

	bool OnRecvMessageSlice(uint32_t sliceIdx, const uint8_t *pSlice, uint16_t sliceLen)
	{
		if(_vbSliceReceived[sliceIdx])
		{
			_numDuplicatedSliceReceived++;
			return false;
		}
		if(sliceIdx >= _vbSliceReceived.size())
			return false;
		uint16_t expectedSliceLen = uint16_t(std::min(_dataLen - sliceIdx * MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize, MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize));
		if(expectedSliceLen != sliceLen)
			return false;

		if(_data.size() == 0)
			return true;

		memcpy(&_data[sliceIdx * MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize], pSlice, sliceLen);
		_vbSliceReceived[sliceIdx] = true;
		_numUniqueSliceReceived++;
		_lastIncomingDataTime = uint64_t(os::Timestamp::Get());

		return true;
	}

	uint64_t GetLastIncomingDataTime() const
	{
		return _lastIncomingDataTime;
	}

	const uint8_t* GetData() const
	{
		return _data.size() > 0 ? &_data[0] : nullptr;
	}

	uint32_t  GetDataLen() const
	{
		return uint32_t(_data.size());
	}

	bool IsDone() const
	{
		return _numUniqueSliceReceived == uint32_t(_vbSliceReceived.size());
	}

	bool PullMessageAcknowledge()
	{
		if(IsDone() && !_bMessageAcknowledgeSent)
		{
			_bMessageAcknowledgeSent = true;
			return true;
		}

		return false;
	}

	void OnMessageAcknowledgeLost()
	{
		_bMessageAcknowledgeSent = false;
	}

	void OnMessageAcknowledgeAcked()
	{
		// No need to do anything
	}

	uint32_t GetNumDuplicatedSlicesReceived() const
	{
		return _numDuplicatedSliceReceived;
	}

	uint32_t GetNumUniqueSlicesReceived() const
	{
		return _numUniqueSliceReceived;
	}

	uint32_t GetTotalSlices() const
	{
		return uint32_t(_vbSliceReceived.size());
	}

	uint32_t GetTotalLen() const
	{
		return _dataLen;
	}

	uint32_t GetId() const
	{
		return _msgId;
	}
};

} // namespace upw