#include "../netsvc_core.h"
#include "mlt_packet.h"
#include "mlt_tunnel.h"

#pragma warning(error:4334)

//#define RECORD_PACKET_HISTORY
//#define ACK_DEBUG

#ifdef ACK_DEBUG
void AckDebugLog(uint32_t tunnelid, const char* line)
{
	FILE* fp = fopen(("tunnel" + std::to_string(tunnelid) + "_ackdebug.txt").c_str(), "a");
	fprintf(fp, "%llu: %s\n", uint64_t(os::Timestamp::Get()), line);
	fprintf(fp, "%llu: %s\n", uint64_t(os::Timestamp::Get()), line);
	fclose(fp);
}
#endif

namespace upw
{
MLT_Tunnel::MLT_Tunnel(NetworkServiceCore* p, const MLT_TunnelCreateInfo &createInfo, uint32_t tunnelId, const rt::String_Ref &connectionData)
	: _pCore(p)
	, _CreateInfo(createInfo)
	, _TunnelId(tunnelId)
	, _ConnectionData(connectionData)
	, _TunnelCreationTime(os::Timestamp::Get())
	, _SessionId(os::Timestamp::Get())
{
	_NoTaskSince = _TunnelCreationTime;
	_NoTaskProgressSince = _TunnelCreationTime;

	_ResetRecvBuffer();
	// OnAttach() should not be called here but rather in MultiLinkTunnels::_CreateTunnel(), when the tunnel is fully registered.
	// The reason is that this callback might trigger a call into MultiLinkTunnels but the lock is still not hold up in the call stack.
	//_CreateInfo.EventHandler->OnAttach(MLT_TUNNEL_HANDLE(_TunnelId));
}

MLT_Tunnel::~MLT_Tunnel()
{
	EnterCSBlock(_CS);

	Close(false, false);

	// different from the OnAttach() call, OnDetach() must be called at the end of the destructor.
	// The reason is that it notifies the event handler that it's no longer being used, hence it might get deallocated.
	_CreateInfo.EventHandler->OnDetach(MLT_TUNNEL_HANDLE(_TunnelId));
}

uint16_t MLT_Tunnel::_GetFastestLinkLatency() const
{
	EnterCSBlock(_CS);

	uint16_t latency = 0xffff;
	for(auto& itor : _ConnectedLinkIds)
	{
		auto itor2 = _IdToLinks.find(itor);
		if(itor2 != _IdToLinks.end())
			latency = std::min(latency, itor2->second->GetLatency());
	}

	return latency;
}

uint16_t MLT_Tunnel::_GetLatency(uint8_t range) const
{
	EnterCSBlock(_CS);

	uint64_t curTime = uint64_t(os::Timestamp::Get());
	uint64_t numEntry = _PacketLatencyEntryCountRecentHistory.GetTotalValue(curTime, range);
	if(numEntry == 0)
		return _GetFastestLinkLatency();
	else
		return _PacketLatencyRecentHistory.GetTotalValue(curTime, range) / numEntry;
}

void MLT_Tunnel::OnTick(uint32_t tick_in_100ms, int64_t net_ts_in_ms)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return;

	for(auto &itor : _IdToLinks)
		itor.second->OnTick(tick_in_100ms, net_ts_in_ms);

	_MaintainConnectedLinkList(tick_in_100ms);

	for(auto &itor : _PendingDeleteLinkIds)
		_IdToLinks.erase(itor);

	_SendBatchAckPacket(false);

	_PerformNextAckCheck(false, false);

	if(tick_in_100ms % 10 == 0)
	{
		uint32_t latency;
		uint32_t lossRate;
		GetTunnelLatencyAndPacketLossRate(1, latency, lossRate);
		if(lossRate > 500)
		{
			uint32_t targetSize = _SendWindowCurSize * (100 - lossRate / 100) / 100;		// shrink window proportional to the drop rate
			targetSize = std::max(targetSize, 64u);											// keep minimal windows size of 64 (same as initial value), so that a high drop rate doesn't close the window completely
			_LOG("send window -: " << _SendWindowCurSize << " -> " << targetSize << ", lossRate = " << lossRate / 100);
			_SendWindowCurSize = targetSize;
		}
		else if(_IsSendWindowFull())
		{
			uint64_t curTime = uint64_t(os::Timestamp::Get());
			uint32_t curTimeOffset = curTime - _TunnelCreationTime;
			uint32_t idx = _NextAckCheckSN % _SendWindowBufferSize;
			if(!_SentPacketAcked[idx])
			{
				uint32_t ellapsedTime = curTimeOffset - _SentPacketTime[idx];
				uint32_t targetSendWindowSize = std::min(_RTO / ellapsedTime * _SendWindowCurSize * 9 / 10, _SendWindowBufferSize);
				if(targetSendWindowSize > _SendWindowCurSize)
				{
					uint32_t deltaWindow = (targetSendWindowSize - _SendWindowCurSize) / 8;
					_LOG("send window +: " << _SendWindowCurSize << " -> " << _SendWindowCurSize + deltaWindow << ", target = " << targetSendWindowSize << ", RTO = " << _RTO << ", ellapsedTime = " << ellapsedTime);
					_SendWindowCurSize += deltaWindow;
				}
			}
		}

		//if(GetStatus() == Status::Connected)
		//{
		//	_LOG("SRTT = " << _SRTT << ", DevRTT = " << _DevRTT << ", RTO = " << _RTO << ", LossRate = " << lossRate / 100);
		//}
	}

	for(auto& itor : _IncomingFiles)
	{
		itor.second->OnTick();
	}

	if(tick_in_100ms % 10 == 0)
	{
		if(_OutgoingMessages.size() == 0 && _IncomingMessages.size() == 0 && _OutgoingFiles.size() == 0 && _IncomingFiles.size() == 0)
		{
			if(_NoTaskSince == 0)
				_NoTaskSince = uint64_t(os::Timestamp::Get());
		}
		else
			_NoTaskSince = 0;

		//if(_IncomingFiles.size())
		//{
		//	for(auto& itor : _IncomingFiles)
		//		_LOG("speed = " << itor.second->GetDownloadSpeed() << ", slice pkt = " << _numRecvFileSlicePkt << ", slice pkt suc = " << _numSucRecvFileSlicePkt);
		//}
		//if(_OutgoingFiles.size())
		//{
		//	for(auto& itor : _OutgoingFiles)
		//		_LOG("pull = " << itor.second->GetNumPullSlice() << ", ack = " << itor.second->GetNumAcks() << ", lost = " << itor.second->GetNumLosts());
		//}
	}

	// TODO: detect outdated queued messages and files and notify send failure

	//uint64_t curTime = uint64_t(os::Timestamp::Get());

	//{
	//	std::set<uint32_t> toDropSet;
	//	for(auto &itor : _IncomingMessages)
	//		if(itor.second->GetLastIncomingDataTime() < curTime - _IncomingMessageTimeout)
	//			toDropSet.emplace(itor.first);
	//	for(auto &itor : toDropSet)
	//	{
	//		_IncomingMessages.erase(itor);
	//		_LOG("[MLT] Dropping timed-out message with id " << itor);
	//	}
	//}

	//if(tick_in_100ms % 10 == 0)
	//{
	//	if(_OutgoingMessages.size())
	//	{
	//		_LOG(_OutgoingMessages.size() << " outgoing messages:");
	//		for(auto &itor : _OutgoingMessages)
	//		{
	//			std::shared_ptr<MLT_OutgoingMessage> ptr = itor.second;
	//			uint32_t completion = uint32_t(double(ptr->GetTotalSent() - ptr->GetTotalLost() - ptr->GetPending()) * 100 / ptr->GetTotalSlices());
	//			uint32_t dropRate = uint32_t(double(ptr->GetTotalLost()) * 100 / (ptr->GetTotalSent() - ptr->GetPending()));
	//			_LOG("  " << ptr->GetId() << ": " << ptr->GetTotalLen() << " (" << completion << "%), drop rate " << dropRate << "% (" << ptr->GetTotalLost() << " / " << ptr->GetTotalSent() - ptr->GetPending() << ")");
	//		}
	//	}
	//	if(_IncomingMessages.size())
	//	{
	//		_LOG(_IncomingMessages.size() << " incoming messages:");
	//		for(auto &itor : _IncomingMessages)
	//		{
	//			std::shared_ptr<MLT_IncomingMessage> ptr = itor.second;
	//			uint32_t completion = uint32_t(double(ptr->GetNumUniqueSlicesReceived()) * 100 / ptr->GetTotalSlices());
	//			_LOG("  " << ptr->GetId() << ": " << ptr->GetTotalLen() << " (" << completion << "%), dup " << ptr->GetNumDuplicatedSlicesReceived() << " / unique " << ptr->GetNumUniqueSlicesReceived());
	//		}
	//	}
	//}
}

void MLT_Tunnel::_ResetFlags()
{
	_DestinationTunnelId = 0xffffffff;
}

void MLT_Tunnel::_ResetRecvBuffer()
{
	_RecvSNLargest = 0;
	_RecvSNWaitingSmallest = 0;
	memset(_RecvPacketBitMask, 0, sizeof(_RecvPacketBitMask));
	memset(_RecvPacketToAckBitMask, 0, sizeof(_RecvPacketToAckBitMask));
	_LastUnackedPacketSN = 0xffffffffu;
	_LastUnackedPacketRecvTime = 0;
	_FirstUnackedPacketSN = 0xffffffffu;
	_FirstUnackedPacketRecvTime = 0;
	_NumUnackedPackets = 0;
}

bool MLT_Tunnel::_IsSendWindowFull()
{
	EnterCSBlock(_CS);

	return _NextSendSN - _NextAckCheckSN >= _SendWindowCurSize;
}

void MLT_Tunnel::_SendQueuedData()
{
	_SendFileRequests();
	_SendMessageAcknowledges();
	_SendQueuedMessages();
	_SendQueuedFiles();
}

void MLT_Tunnel::_SendQueuedMessages()
{
	EnterCSBlock(_CS);

	if(_IsSendWindowFull() || _Status != Status::Connected)
		return;

	for(auto &itor : _OutgoingMessages)
	{
		uint32_t msgId = itor.second->GetId();
		uint32_t msgTotalLen = itor.second->GetTotalLen();
		{
			const uint8_t *pSlice = nullptr;
			uint16_t sliceLen;
			uint32_t sliceIdx;
			while(itor.second->PullNextSlice(pSlice, sliceLen, sliceIdx) && pSlice)
			{
				if(!_SendMessageDataPacket(msgId, msgTotalLen, sliceIdx, pSlice, sliceLen))
				{
					// This happens if UDP buffer is full. In this case the packet was not sent and we should stop sending data for now
					itor.second->OnSliceLost(sliceIdx);
					return;
				}
				if(_IsSendWindowFull())
					return;
			}
		}
	}
}

void MLT_Tunnel::_SendFileRequests()
{
	EnterCSBlock(_CS);

	if(_IsSendWindowFull() || _Status != Status::Connected)
		return;

	for(auto &itor : _IncomingFiles)
	{
		uint32_t fileId = itor.second->GetId();
		uint32_t blockIdx;
		uint8_t *pSliceMask;
		uint16_t sliceMaskLen;
		auto ptr = itor.second;
		if(ptr->PullBlockRequest(blockIdx, pSliceMask, sliceMaskLen))
		{
			if(!_SendFileRequestBlockPacket(ptr->GetFileHash(), ptr->GetFileSize(), ptr->GetId(), ptr->GetFilePriority(), blockIdx, pSliceMask, sliceMaskLen))
			{
				ptr->OnBlockRequestLost();
				return;
			}
			if(_IsSendWindowFull())
				return;
		}
		else if(ptr->PullFileAcknowledge())
		{
			if(!_SendFileAcknowledgePacket(ptr->GetId()))
			{
				ptr->OnFileAcknowledgeLost();
				return;
			}
			if(_IsSendWindowFull())
				return;
		}
	}
}

void MLT_Tunnel::_SendMessageAcknowledges()
{
	EnterCSBlock(_CS);

	if(_IsSendWindowFull() || _Status != Status::Connected)
		return;

	for(auto& itor : _IncomingMessages)
	{
		uint32_t fileId = itor.second->GetId();
		auto ptr = itor.second;
		if(ptr->PullMessageAcknowledge())
		{
			if(!_SendMessageAcknowledgePacket(ptr->GetId()))
			{
				ptr->OnMessageAcknowledgeLost();
				return;
			}
			if(_IsSendWindowFull())
				return;
		}
	}
}

void MLT_Tunnel::_SendQueuedFiles()
{
	EnterCSBlock(_CS);

	if(_IsSendWindowFull() || _Status != Status::Connected)
		return;

	for(auto &itor : _OutgoingFiles)
	{
		uint32_t fileId = itor.second->GetId();
		{
			const uint8_t *pSlice = nullptr;
			uint16_t sliceLen;
			uint32_t sliceIdx;
			while(itor.second->PullNextSlice(pSlice, sliceLen, sliceIdx) && pSlice)
			{
				if(!_SendFileSlicePacket(fileId, sliceIdx, pSlice, sliceLen))
				{
					// This happens if UDP buffer is full. In this case the packet was not sent and we should stop sending data for now
					itor.second->OnFileSliceLost(sliceIdx);
					return;
				}
				if(_IsSendWindowFull())
					return;
			}
		}
	}
}

bool MLT_Tunnel::_SendMessageAcknowledgePacket(uint32_t msgId)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

	MLT_Packet::PKT_MESSAGE_ACKNOWLEDGE packet;
	packet.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::MessageAcknowledge;
	packet.msgId = msgId;

	bool res = _SendTunnelData(&packet, sizeof(packet), true, false, uint32_t(packet.dataType), msgId);
	_LOG(">> Tunnel MessageAcknowledge " << msgId);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " MA " + std::to_string(msgId) + " [" + std::to_string(packet.AckSNBase) + " " + std::to_string(packet.AckSNMask) + "] [" + std::to_string(packet.TPSN) + "]";
	_Log.push_back(logStr);
#endif

	return res;
}

void MLT_Tunnel::_SendMessageRejectPacket(uint32_t msgId)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return;

	MLT_Packet::PKT_MESSAGE_REJECT packet;
	packet.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::MessageReject;
	packet.msgId = msgId;

	bool res = _SendTunnelData(&packet, sizeof(packet), true, false, uint32_t(packet.dataType), msgId);
	_LOG(">> Tunnel MessageReject " << msgId);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " MR " + std::to_string(msgId) + " [" + std::to_string(packet.AckSNBase) + " " + std::to_string(packet.AckSNMask) + "] [" + std::to_string(packet.TPSN) + "]";
	_Log.push_back(logStr);
#endif
}

bool MLT_Tunnel::_SendMessageDataPacket(uint32_t msgId, uint32_t dataTotalLen, uint32_t sliceIdx, const uint8_t *pSlice, uint16_t sliceLen)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

#pragma pack(push, 1)
	struct MsgDataPacket {
		MLT_Packet::PKT_MESSAGE_DATA_SLICE msgData;
		uint8_t buffer[MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize];
	};
#pragma pack(pop)

	MsgDataPacket adp;
	adp.msgData.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::MessageDataSlice;
	adp.msgData.msgId = msgId;
	adp.msgData.msgTotalLen = dataTotalLen;
	adp.msgData.sliceIdx = sliceIdx;
	memcpy(adp.msgData.slice, pSlice, sliceLen);

	//_LOG("[MLT] Tunnel " << GetTunnelId() << " sending a packet for message id " << msgId << ", slice index " << sliceIdx);

	bool res = _SendTunnelData(&adp.msgData, offsetof(MsgDataPacket, msgData.slice) + sliceLen, true, false, msgId, sliceIdx);
	//_LOG(">> Tunnel MsgData " << msgId << " " << sliceIdx << " " << _NextSendSN);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " MD msg(" + std::to_string(msgId) + ").slice(" + std::to_string(sliceIdx) + ") [" + std::to_string(adp.msgData.AckSNBase) + " " + std::to_string(adp.msgData.AckSNMask) + "] [" + std::to_string(adp.msgData.TPSN) + "]";
	_Log.push_back(logStr);
#endif

	return res;
}

bool MLT_Tunnel::_SendFileSlicePacket(uint32_t fileId, uint32_t sliceIdx, const uint8_t *pSlice, uint16_t sliceLen)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

#pragma pack(push, 1)
	struct FileSlicePacket {
		MLT_Packet::PKT_FILE_SLICE metadata;
		uint8_t buffer[MLT_Packet::PKT_FILE_SLICE::fileSliceSize];
	};
#pragma pack(pop)

	FileSlicePacket fsp;
	fsp.metadata.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileSlice;
	fsp.metadata.fileId = fileId;
	fsp.metadata.sliceIdx = sliceIdx;
	memcpy(fsp.metadata.slice, pSlice, sliceLen);

	//_LOG("[MLT] Tunnel " << GetTunnelId() << " sending a packet for file id " << fileId << ", slice index " << sliceIdx);

	bool res = _SendTunnelData(&fsp.metadata, offsetof(FileSlicePacket, metadata.slice) + sliceLen, true, false, fileId, sliceIdx);
	//_LOG(">> Tunnel FileSlice " << fileId << " " << sliceIdx << " " << _NextSendSN);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " FS file(" + std::to_string(fileId) + ").slice(" + std::to_string(sliceIdx) + ") [" + std::to_string(fsp.metadata.AckSNBase) + " " + std::to_string(fsp.metadata.AckSNMask) + "] [" + std::to_string(fsp.metadata.TPSN) + "]";
	_Log.push_back(logStr);
#endif

	return res;
}

bool MLT_Tunnel::_SendFileRequestBlockPacket(const MLT_FileHash &fileHash, uint64_t fileSize, uint32_t fileId, uint32_t priority, uint32_t blockIdx, const uint8_t *sliceMask, uint16_t sliceMaskLen)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

	MLT_Packet::PKT_FILE_REQUEST_BLOCK packet;
	packet.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileRequestBlock;
	static_assert(sizeof(packet.fileHash) == sizeof(fileHash), "MLT_Packet::PKT_FILE_REQUEST_BLOCK.fileHash and MLT_IncomingFile._fileHash size mismatch");
	memcpy(packet.fileHash, &fileHash, sizeof(fileHash));
	packet.fileSize = fileSize;
	packet.fileId = fileId;
	packet.priority = priority;
	packet.blockIdx = blockIdx;
	if(sizeof(packet.sliceMask) != sliceMaskLen)
	{
		_LOG_ERROR("MLT_Tunnel::_SendFileRequestBlockPacket() parameter sliceMaskLen doesn't match MLT_Packet::PKT_FILE_REQUEST_BLOCK.sliceMask. BUG!");
		return false;
	}
	memcpy(packet.sliceMask, sliceMask, sliceMaskLen);

	_LOG("[MLT] Tunnel " << GetTunnelId() << " sending FileRequestBlock for file id " << fileId << " block index " << blockIdx);

	bool res = _SendTunnelData(&packet, sizeof(MLT_Packet::PKT_FILE_REQUEST_BLOCK), true, false, uint32_t(packet.dataType), fileId);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " FR file(" + std::to_string(fileId) + ").block(" + std::to_string(blockIdx) + ") [" + std::to_string(packet.AckSNBase) + " " + std::to_string(packet.AckSNMask) + "] [" + std::to_string(packet.TPSN) + "]";
	_Log.push_back(logStr);
#endif

	return res;
}

bool MLT_Tunnel::_SendFileAcknowledgePacket(uint32_t fileId)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

	MLT_Packet::PKT_FILE_ACKNOWLEDGE packet;
	packet.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileAcknowledge;
	packet.fileId = fileId;

	bool res = _SendTunnelData(&packet, sizeof(packet), true, false, uint32_t(packet.dataType), fileId);
	_LOG(">> Tunnel FileAcknowledge " << fileId << ", successfully sent = " << (res ? "1" : "0"));

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " FA " + std::to_string(fileId) + " [" + std::to_string(packet.AckSNBase) + " " + std::to_string(packet.AckSNMask) + "] [" + std::to_string(packet.TPSN) + "]";
	_Log.push_back(logStr);
#endif

	return res;
}

bool MLT_Tunnel::_SendFileRejectRequestPacket(uint32_t fileId, uint32_t blockIdx)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

	if(_LastFileCancelRequestPacketTs + _FileCancelRequestMinimalInterval >= uint64_t(os::Timestamp::Get()))
		return false;

	MLT_Packet::PKT_FILE_REJECT_REQUEST packet;
	packet.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileRejectRequest;
	packet.fileId = fileId;
	packet.blockIdx = blockIdx;

	bool res = _SendTunnelData(&packet, sizeof(packet), true, false, uint32_t(packet.dataType), fileId);
	_LastFileCancelRequestPacketTs = uint64_t(os::Timestamp::Get());
	_LOG(">> Tunnel FileRejectRequest " << fileId);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " FJ " + std::to_string(fileId) + " [" + std::to_string(packet.AckSNBase) + " " + std::to_string(packet.AckSNMask) + "] [" + std::to_string(packet.TPSN) + "]";
	_Log.push_back(logStr);
#endif

	return res;
}

bool MLT_Tunnel::_SendFileCancelRequestPacket(uint32_t fileId)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

	MLT_Packet::PKT_FILE_CANCEL_REQUEST packet;
	packet.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileCancelRequest;
	packet.fileId = fileId;

	bool res = _SendTunnelData(&packet, sizeof(packet), false, false, uint32_t(packet.dataType), fileId);		// FileCancelRequest packets are not tracked
	_LOG(">> Tunnel FileCancelRequest " << fileId);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr;
	logStr = ">> " + std::to_string(res) + " FC " + std::to_string(fileId) + " [" + std::to_string(packet.AckSNBase) + " " + std::to_string(packet.AckSNMask) + "] [" + std::to_string(packet.TPSN) + "]";
	_Log.push_back(logStr);
#endif

	return res;
}


void MLT_Tunnel::_MaintainConnectedLinkList(uint32_t tick_in_100ms)
{
	EnterCSBlock(_CS);

	// if there are too many connected links, remove low quality ones
	if(_ConnectedLinkIds.size() > _MaximumConnectedLinks)
	{
		std::shared_ptr<MLT_Link> pDropLink = nullptr;
		for(auto &itor : _ConnectedLinkIds)
		{
			std::shared_ptr<MLT_Link> pLink = _IdToLinks.find(itor)->second;
			// TODO: do not drop links that are being actively used, e.g. file still being transfered over it.
			if(pDropLink == nullptr || pDropLink->GetLatency() < pLink->GetLatency())
				pDropLink = pLink;
		}

		if(pDropLink)
		{
			_RemoveLink(pDropLink->GetLinkId());
			//_LOG("[MLT] Removing connected link " << pDropLink->GetLinkId() << " of tunnel " << GetTunnelId());
		}
	}

	// if there are too few connected links, establish more
	if(_ConnectedLinkIds.size() > 0 && _ConnectedLinkIds.size() < _MinimumConnectedLinks && _LastAccessPointPacketTs + _AccessPointPacketMinimalInterval < uint64_t(os::Timestamp::Get()))
	{
		_SendAccessPointsPacket();
	}

	// if there are no connected links, try revive some backup bouncer links
	if(_ConnectedLinkIds.size() == 0 && _backupBouncerLinkDestinations.size() > 0 && tick_in_100ms % 50 == 0)	// try one link every 5 seconds
	{
		uint32_t idx = (tick_in_100ms / 50) % _backupBouncerLinkDestinations.size();
		CreateLinkAndSendHandshake(_backupBouncerLinkDestinations[idx].second, &_backupBouncerLinkDestinations[idx].first);
		_LOG("[MLT] Tunnel " << _TunnelId << ": Trying to revive backup bouncer link " << idx << ": " << tos(_backupBouncerLinkDestinations[idx].first) << " -> " << tos(_backupBouncerLinkDestinations[idx].second));
	}

	// if there are no direct ones, try revive some backup direct links
	if(_backupDirectLinkDestinations.size() > 0 && tick_in_100ms % 50 == 0)	// try one link every 5 seconds
	{
		bool bHasDirectLinks = false;
		for(auto& itor : _ConnectedLinkIds)
		{
			auto itor2 = _IdToLinks.find(itor);
			if(itor2 != _IdToLinks.end() && itor2->second->IsDirectLink())
			{
				bHasDirectLinks = true;
				break;
			}
		}

		if(!bHasDirectLinks)
		{
			uint32_t idx = (tick_in_100ms / 50) % _backupDirectLinkDestinations.size();
			CreateLinkAndSendHandshake(_backupDirectLinkDestinations[idx], nullptr);
			_LOG("[MLT] Tunnel " << _TunnelId << ": Trying to revive backup direct link " << idx << ": " << tos(_backupDirectLinkDestinations[idx]));
		}
	}
}

std::shared_ptr<MLT_Link> MLT_Tunnel::_CreateLink(const NetworkAddress &dstAddr, const NetworkAddress *bouncerAddr)
{
	EnterCSBlock(_CS);

	// Do not allow links bouncing from target itself
	// ideally should also not allow links bouncing from own node self.
	if(bouncerAddr && *bouncerAddr == dstAddr)
		return nullptr;

	const NetworkAddress &directReceiverAddr = bouncerAddr ? *bouncerAddr : dstAddr;

	auto itor = _AddrToLinks.find(directReceiverAddr);
	if(itor != _AddrToLinks.end())
		return itor->second;

	std::shared_ptr<MLT_Link> pLink = std::make_shared<MLT_Link>(dstAddr, bouncerAddr, this, _NextLinkId);
	_AddrToLinks.emplace(directReceiverAddr, pLink);
	_IdToLinks.emplace(_NextLinkId, pLink);
	_NextLinkId++;

	{
		rt::String str;
		if(!bouncerAddr)
			str = rt::SS("[") + tos(dstAddr) + rt::SS("]");
		else
			str = rt::SS("[") + tos(*bouncerAddr) + rt::SS(" -> ") + tos(dstAddr) + rt::SS("]");
		_LOG("[MLT] Tunnel " << GetTunnelId() << " creating new Link to " << str);
	}

	return pLink;
}

bool MLT_Tunnel::CreateLinkAndSendHandshake(const NetworkAddress &dstAddr, const NetworkAddress *bouncerAddr)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

	std::shared_ptr<MLT_Link> pLink = _CreateLink(dstAddr, bouncerAddr);

	if(!pLink)
		return false;

	pLink->SendPacket(nullptr, 0, true, true);

	return true;
}

void MLT_Tunnel::CreateLinksFromAPs(const NodeAccessPoints& aps)
{
	EnterCSBlock(_CS);

	{
		for(uint8_t i = 0; i < aps.PublicCount.v4; i++)
		{
			const NetworkAddress dstAddr = aps.GetPublicIPv4()[i];
			CreateLinkAndSendHandshake(dstAddr, nullptr);
		}
		if(_pCore->HasIPv6())
		{
			for(uint8_t i = 0; i < aps.PublicCount.v6; i++)
			{
				const NetworkAddress dstAddr = aps.GetPublicIPv6()[i];
				CreateLinkAndSendHandshake(dstAddr, nullptr);
			}
		}
		for(uint8_t i = 0; i < aps.LocalCount.v4; i++)
		{
			const NetworkAddress dstAddr = aps.GetLocalIPv4()[i];
			CreateLinkAndSendHandshake(dstAddr, nullptr);
		}
		if(_pCore->HasIPv6())
		{
			for(uint8_t i = 0; i < aps.LocalCount.v6; i++)
			{
				const NetworkAddress dstAddr = aps.GetLocalIPv6()[i];
				CreateLinkAndSendHandshake(dstAddr, nullptr);
			}
		}
		for(uint8_t i = 0; i < aps.BouncerCount.v4; i++)
		{
			const NodeAccessPoints::Bouncer_IPv4 &bouncer = aps.GetBouncerIPv4()[i];
			const NetworkAddress bouncerAddr = bouncer.Ip;
			const NetworkAddress dstAddr = bouncer.IsDestinationIPv6() ? NetworkAddress(aps.GetBouncerDestinationIPv6(bouncer.DestinationIndex)) : NetworkAddress(aps.GetBouncerDestinationIPv4(bouncer.DestinationIndex));
			CreateLinkAndSendHandshake(dstAddr, &bouncerAddr);
		}
		if(_pCore->HasIPv6())
		{
			for(uint8_t i = 0; i < aps.BouncerCount.v6; i++)
			{
				const NodeAccessPoints::Bouncer_IPv6& bouncer = aps.GetBouncerIPv6()[i];
				const NetworkAddress bouncerAddr = bouncer.Ip;
				const NetworkAddress dstAddr = bouncer.IsDestinationIPv6() ? NetworkAddress(aps.GetBouncerDestinationIPv6(bouncer.DestinationIndex)) : NetworkAddress(aps.GetBouncerDestinationIPv4(bouncer.DestinationIndex));
				CreateLinkAndSendHandshake(dstAddr, &bouncerAddr);
			}
		}
	}
}

bool MLT_Tunnel::_ProcessIncomingSessionId(uint64_t incomingSenderSessionId, uint64_t incomingRecipientSessionId, bool& outShouldNotifyNewSessionId, bool &outShouldProcessTunnelData)
{
	// This should never happen, the sender should always know its own session id
	if(incomingSenderSessionId == 0xffffffffffffffffull)
		return false;

	outShouldNotifyNewSessionId = false;
	// If incomingRecipientSessionId is wild card, it means the destination doesn't know our session id yet.
	// Regard it as if it's the correct id, but remember to notify destination of our session id
	if(incomingRecipientSessionId == 0xffffffffffffffffull)
	{
		outShouldNotifyNewSessionId = true;
		_LOG("[MLT] Tunnel " << _TunnelId << ": Destination doesn't know our session id " << _SessionId << ". Will notify");
		incomingRecipientSessionId = _SessionId;
	}
	// if we don't know destination's session id yet, grab from incoming sender session id
	if(_DestinationSessionId == 0xffffffffffffffffull)
	{
		_DestinationSessionId = incomingSenderSessionId;
	}

	// There are 9 cases if we compare:
	//   incomingSenderSessionId (Ssid) and _DestinationSessionId, and
	//   incomingRecipientSessionId (Rsid) and _SessionId
	// as in the following table:
	// 
	//     \ Rsid  | < | = | > | _SessionId
	// Ssid \      |   |   |   |
	// -------------------------
	//       <     | 1 | 2 | 3 |
	// -------------------------
	//       =     | 4 | 5 | 6 |
	// -------------------------
	//       >     | 7 | 8 | 9 |
	// -------------------------
	// _DestinationSessionId
	//
	// 1. Ssid < _DestinationSessionId, Rsid < _SessionId
	//   Possible case: a.) Delayed packet from old session. b.) sender system time went backwards and meanwhile started a new session. Recipient also started a new session.
	//   Reply: ignore completely
	// 2. Ssid < _DestinationSessionId, Rsid = _SessionId
	//   Possible case: a.) Delayed packet from old session. b.) sender system time went backwards and meanwhile started a new session.
	//   Reply: ignore completely
	// 3. Ssid < _DestinationSessionId, Rsid > _SessionId
	//   Possible case: a.) Delayed packet from old session. b.) sender system time went backwards and meanwhile started a new session. Recipient system time also went backwards and started a new session.
	//   Reply: ignore completely. (Not ideal but keep it this way for now)
	// 4. Ssid = _DestinationSessionId, Rsid < _SessionId
	//   Possible case: Recipient has started a new session, sender doesn't know
	//   Reply: Send an empty packet to notify the new _SessionId. Ignore the incoming packet content.
	// 5. Ssid = _DestinationSessionId, Rsid = _SessionId
	//   Possible case: Everything in order
	//   Reply: As normal.
	// 6. Ssid = _DestinationSessionId, Rsid > _SessionId
	//   Possible case: Recipient system time changed backwards and started a new session.
	//   Reply: ignore completely. (Not ideal but keep it this way for now)
	// 7. Ssid > _DestinationSessionId, Rsid < _SessionId
	//   Possible case: Sender just started a new session, Recipient also started a new session and sender doesn't know.
	//   Reply: _DestinationSessionId <- Ssid, OnDestSessionChange(), send empty packet to notify the new _SessionId. ignore packet content.
	// 8. Ssid > _DestinationSessionId, Rsid = _SessionId
	//   Possible case: Sender just started a new session
	//   Reply: _DestinationSessionId <- Ssid, OnDestSessionChange(). Process packet content.
	// 9. Ssid > _DestinationSessionId, Rsid > _SessionId
	//   Possible case: Sender just started a new session. Recipient system time changed backwards and started a new session.
	//   Reply: ignore completely. (Not ideal but keep it this way for now)
	//
	// Summary:
	//   1. 2. 3. 6. 9 : ignore completely
	//   4. 7: Reply with empty packet
	//   5. 8. : Process incoming packet content
	//   7. 8. : OnDestSessionChange(), this turns 7 -> 4, 8 -> 5

	// case 1, 2, 3, 6, 9
	if(incomingSenderSessionId < _DestinationSessionId || incomingRecipientSessionId > _SessionId)
	{
		char signA = _SessionId < incomingRecipientSessionId ? '<' : (_SessionId > incomingRecipientSessionId ? '>' : '=');
		char signB = _DestinationSessionId < incomingSenderSessionId ? '<' : (_DestinationSessionId > incomingSenderSessionId ? '>' : '=');
		_LOG_WARNING("[MLT] Tunnel " << _TunnelId << ": Invalid session ids received. local: " << _SessionId << " " << signA <<  " " << incomingRecipientSessionId << ", destination: " << _DestinationSessionId << " " << signB << " " << incomingSenderSessionId);
		return false;
	}

	// case 4, 7
	if(incomingRecipientSessionId < _SessionId && incomingSenderSessionId >= _DestinationSessionId)
	{
		outShouldNotifyNewSessionId = true;
		_LOG("[MLT] Tunnel " << _TunnelId << ": Destination knows an older value (" << incomingRecipientSessionId << ") of our session id " << _SessionId << ". Will notify.");
	}

	// case 5, 8
	outShouldProcessTunnelData = false;
	if(incomingRecipientSessionId == _SessionId && incomingSenderSessionId >= _DestinationSessionId)
		outShouldProcessTunnelData = true;

	// case 7, 8
	bool bHandleDestinationSessionChange = false;
	if(incomingRecipientSessionId <= _SessionId && incomingSenderSessionId > _DestinationSessionId)
	{
		bHandleDestinationSessionChange = true;
		_LOG("[MLT] Tunnel " << _TunnelId << ": Destination has a newer session id " << incomingSenderSessionId << " than we know (" << _DestinationSessionId << "). Will update.");
	}

	if(bHandleDestinationSessionChange)
		_OnDestinationSessionIdChange(incomingSenderSessionId);

	return true;
}

void MLT_Tunnel::_OnDestinationSessionIdChange(uint64_t newDestinationSessionId)
{
	// Already sent packets were sent to old session, ignore them and don't check their ACKs.
	_NextAckCheckSN = _NextSendSN;

	// Since the session is new to us, reset the recv flags
	_ResetRecvBuffer();

	// Drop all links
	_IdToLinks.clear();
	_AddrToLinks.clear();
	if(_ConnectedLinkIds.size() > 0)
	{
		_ConnectedLinkIds.clear();
	}

	// clear all incoming messages and receive history
	_IncomingMessages.clear();
	_previouslyReceivedMessages.clear();

	// Reset progress of outgoing messages
	for(auto& itor : _OutgoingMessages)
	{
		std::shared_ptr<MLT_OutgoingMessage> ptr = itor.second;
		ptr->ResetProgress();
	}

	// Drop all outgoing files
	for(auto& itor : _OutgoingFiles)
	{
		_CreateInfo.EventHandler->OnFileUnrequest(GetHandle(), itor.second->GetFileReader());
	}
	_OutgoingFiles.clear();

	// drop incoming file history
	_previouslyReceivedFiles.clear();

	// flush current incoming file buffer and re-send the requests
	for(auto& itor : _IncomingFiles)
	{
		itor.second->OnDestinationSessionChange();
	}

	_DestinationSessionId = newDestinationSessionId;

	if(_Status == Status::Closed)
		_Status = Status::Disconnected;
}

void MLT_Tunnel::OnRecv(MLT_IncomingPacketParser &parser, const NetworkAddress &senderAddr, const NetworkAddress *pBouncerAddr)
{
	EnterCSBlock(_CS);

	if(!parser.ParseBody(_CreateInfo.Secret))
		return;
	if(!parser.GetBodyHeader())
		return;

	bool bShouldNotifyNewSessionId = false;
	bool bShouldProcessTunnelData = false;
	if(!_ProcessIncomingSessionId(parser.GetBodyHeader()->senderSessionId, parser.GetBodyHeader()->recipientSessionId, bShouldNotifyNewSessionId, bShouldProcessTunnelData))
		return;

	_DestinationTunnelId = parser.GetBodyHeader()->senderTunnelId;

	std::shared_ptr<MLT_Link> pLink = nullptr;
	if(parser.GetBodyHeader()->recipientLinkId != 0xffffffff)
	{
		auto itor = _IdToLinks.find(parser.GetBodyHeader()->recipientLinkId);
		if(itor != _IdToLinks.end())
			pLink = itor->second;

		// the packet is sent directly to the link id, so the destination knows our link id
		if(pLink)
			pLink->SetDestinationKnowsOurLinkId(true);
	}

	//const NetworkAddress *pDirectSenderAddr = pBouncerAddr ? pBouncerAddr : &senderAddr;

	//if(!pLink)
	//{
	//	auto itor = _AddrToLinks.find(*pDirectSenderAddr);
	//	if(itor != _AddrToLinks.end())
	//	{
	//		pLink = itor->second;
	//		_LOG("Recognized link " << pLink->GetLinkId() << " from addr " << tos(*pDirectSenderAddr));
	//	}
	//}

	if(!pLink)
		pLink = _CreateLink(senderAddr, pBouncerAddr);

	// Technically we could allow data to be sent over unestablished links, but it's not part of the protocol
	if(!pLink)
		return;

	pLink->OnRecv(parser);

	if(bShouldNotifyNewSessionId)
		_SendBatchAckPacket(true);

	if(bShouldProcessTunnelData && parser.GetTunnelData())
		_OnRecvTunnelData(parser.GetTunnelData(), parser.GetTunnelDataLen());

	return;
}

void MLT_Tunnel::_SendBatchAckPacket(bool bForce)
{
	uint64_t curTime = uint64_t(os::Timestamp::Get());
	if(curTime - _LastBatchAckPacketTs <= _BatchAckPacketMinimalInterval && !bForce && _NumUnackedPackets < 32)		// ignore interval if forced or there are >= 32 unacked packets
		return;
	if(_NumUnackedPackets != 0 || bForce)
	{
		char buffer[offsetof(MLT_Packet::PKT_BATCH_ACK, AckMask) + MLT_Packet::PKT_BATCH_ACK::AckMaskMaxSizeInBytes];
		MLT_Packet::PKT_BATCH_ACK &header = *(MLT_Packet::PKT_BATCH_ACK*)buffer;
		header.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::BatchAck;

		{
			header.lastUnackedPacketSN = _LastUnackedPacketSN;
			if(_LastUnackedPacketSN != 0xffffffffu)
				header.lastUnackedPacketAckDelay = uint16_t(std::min(curTime - _LastUnackedPacketRecvTime, (uint64_t)65536));

			header.firstUnackedPacketSN = _FirstUnackedPacketSN;
			if(_FirstUnackedPacketSN != 0xffffffffu)
				header.firstUnackedPacketAckDelay = uint16_t(std::min(curTime - _FirstUnackedPacketRecvTime, (uint64_t)65536));

			header.SNBegin = _RecvSNWaitingSmallest;
			header.SNEnd = _RecvSNLargest;
			for(uint32_t i = header.SNBegin / 64, j = 0; i <= header.SNEnd / 64; i++, j++)
				header.AckMask[j] = _RecvPacketBitMask[i % (_RecvWindowBufferSize / 64)];

#ifdef ACK_DEBUG
			{
				std::string str = " >> ";
				for(uint32_t i = header.SNBegin, j = 0; i <= header.SNEnd; i++, j++)
					if(_RecvPacketBitMask[(i % _RecvWindowBufferSize) / 64] & (1ull << (i % 64)))
						str += " " + std::to_string(i);
				if(str.size() > 4)
					AckDebugLog(GetTunnelId(), str.c_str());
			}
#endif
		}

		bool res = _SendTunnelData(&header, MLT_Packet::PKT_BATCH_ACK::GetSize(header.SNBegin, header.SNEnd), false, true, uint32_t(header.dataType), 0);
		if(res)
		{
			_LastUnackedPacketSN = 0xffffffffu;
			_FirstUnackedPacketSN = 0xffffffffu;
			_LastBatchAckPacketTs = curTime;
			_NumUnackedPackets = 0;
		}

#ifdef RECORD_PACKET_HISTORY
		std::string logStr;
		logStr = ">> " + std::to_string(res) + " BA [" + std::to_string(header.AckSNBase) + " " + std::to_string(header.AckSNMask) + "] [" + std::to_string(header.TPSN) + "]";
		_Log.push_back(logStr);
#endif
	}
}

void MLT_Tunnel::_ProcessIncomingPacketQoS(MLT_Packet::PKT_TUNNEL_DATA_HEADER *pHeader)
{
	uint32_t TPSN = pHeader->TPSN;
	if(TPSN != 0xffffffffu)
	{
		// if the incoming SN is larger than current largest
		if(TPSN > _RecvSNLargest)
		{
			// if it's too large (i.e. the distance between it and the smallest is larger than recv buffer size), the lower side of recv buffer will be overwritten, therefore we need to send the current ack data before that happens
			if(TPSN >= _RecvSNWaitingSmallest + _RecvWindowBufferSize && _NumUnackedPackets != 0)
				_SendBatchAckPacket(true);

			// reset _RecvPacketBitMask and _RecvPacketToAckBitMaskbetween in range (_RecvSNLargest, TPSN]
			{
				// expand size is larger than buffer total size, simply zero it
				if(TPSN >= _RecvSNLargest + _RecvWindowBufferSize - 1)
				{
					memset(_RecvPacketBitMask, 0, sizeof(_RecvPacketBitMask));
					memset(_RecvPacketToAckBitMask, 0, sizeof(_RecvPacketToAckBitMask));
				}
				else
				{
					// if the 2 ends are in the same 64-bit slot
					if((_RecvSNLargest + 1) / 64 == TPSN / 64)
					{
						// generate a mask with 0 bits from _RecvSNLargest + 1 to TPSN, inclusive
						uint64_t mask1 = (1ull << ((_RecvSNLargest + 1) % 64)) - 1;		// bits below _RecvSNLargest + 1 are set to 1
						uint64_t mask2 = (((1ull << (TPSN % 64)) - 1) << 1) | 1;		// bits at and below TPSN are set to 1
						uint64_t mask3 = ~(mask2 ^ mask1);								// bits from _RecvSNLargest + 1 to TPSN, inclusive, are set to 0
						uint32_t idx = (TPSN % _RecvWindowBufferSize) / 64;
						_RecvPacketBitMask[idx] &= mask3;
						_RecvPacketToAckBitMask[idx] &= mask3;
					}
					else
					{
						// The range could be split into 3 parts

						// Part 1: The 64-bit slot where _RecvSNLargest + 1 is. Set higher bits in this slot starts starting from _RecvSNLargest + 1 to 0
						uint32_t cur = _RecvSNLargest + 1;
						if(cur % 64 != 0)
						{
							uint64_t mask = (1ull << (cur % 64)) - 1;					// bits below cur are 1
							uint32_t idx = (cur % _RecvWindowBufferSize) / 64;
							_RecvPacketBitMask[idx] &= mask;							// set bits at and above cur to 0
							_RecvPacketToAckBitMask[idx] &= mask;

							cur += 64 - cur % 64;										// snap to next multiple of 64
						}
						// now cur is guaranteed to be multiple of 64

						// Part 2: All slots (possibly 0) between but not including where _RecvSNLargest + 1 is and where TPSN is. Fill these slots with 0
						for(uint32_t slot = cur / 64; slot < TPSN / 64; slot++)
							_RecvPacketBitMask[slot % (_RecvWindowBufferSize / 64)] = _RecvPacketToAckBitMask[slot % (_RecvWindowBufferSize / 64)] = 0;

						// Part 3: The 64-bit slot where TPSN is. Set lower bits in the same slot up to TPSN to 0
						{
							uint64_t mask = (((1ull << (TPSN % 64)) - 1) << 1) | 1;		// bits at and below cur are 1
							mask = ~mask;												// bits above cur are 1
							uint32_t idx = (TPSN % _RecvWindowBufferSize) / 64;
							_RecvPacketBitMask[idx] &= mask;							// set bits at and below cur to 0
							_RecvPacketToAckBitMask[idx] &= mask;
						}
					}
				}
			}

			for(uint32_t i = _RecvSNLargest + 1; i <= TPSN; i++)
				if((_RecvPacketBitMask[(i % _RecvWindowBufferSize) / 64] & (1ull << (i % 64))) != 0)
				{
					_LOG_ERROR(i << " in [" << _RecvSNLargest + 1 << ", " << TPSN << "] is not set to 0");
				}
			// expand the upper end of window from _RecvSNLargest to TPSN
			_RecvSNLargest = TPSN;
		}
		// update _RecvSNWaitingSmallest with incoming WaitingAckSN
		if(pHeader->WaitingAckSN > _RecvSNWaitingSmallest && pHeader->WaitingAckSN <= _RecvSNLargest)
			_RecvSNWaitingSmallest = pHeader->WaitingAckSN;
		// make sure that _RecvSNWaitingSmallest is not outside the buffer window
		if(_RecvSNLargest - _RecvSNWaitingSmallest >= _RecvWindowBufferSize)
			_RecvSNWaitingSmallest = _RecvSNLargest - _RecvWindowBufferSize;
		// set the bit for the received packet
		if(TPSN <= _RecvSNLargest && TPSN >= _RecvSNWaitingSmallest)
		{
			uint32_t idx = TPSN % _RecvWindowBufferSize;
			if((_RecvPacketBitMask[idx / 64] & (1ull << (idx % 64))) == 0)
			{
				_RecvPacketBitMask[idx / 64] |= 1ull << (idx % 64);
				_RecvPacketToAckBitMask[idx / 64] |= 1ull << (idx % 64);

				uint64_t curTime = uint64_t(os::Timestamp::Get());
				if(_FirstUnackedPacketSN == 0xffffffffu)
				{
					_FirstUnackedPacketSN = TPSN;
					_FirstUnackedPacketRecvTime = curTime;
				}
				_LastUnackedPacketSN = TPSN;
				_LastUnackedPacketRecvTime = curTime;
				_NumUnackedPackets++;
#ifdef ACK_DEBUG
				if(pHeader->dataType == MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileSlice)
				{
					const MLT_Packet::PKT_FILE_SLICE& dataSlice = *(MLT_Packet::PKT_FILE_SLICE*)pHeader;
					std::string str = "   < " + std::to_string(pHeader->TPSN) + "(slice " + std::to_string(dataSlice.sliceIdx) + ")";
					AckDebugLog(GetTunnelId(), str.c_str());
				}
#endif
			}
		}
		else
		{
			_LOG_ERROR("Old packet incoming " << TPSN << " <<< [" << _RecvSNWaitingSmallest << ", " << _RecvSNLargest << "]");
		}
	}
}

void MLT_Tunnel::_OnRecvTunnelData(const uint8_t *pData, uint16_t dataLen)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return;

	if(dataLen < sizeof(MLT_Packet::PKT_TUNNEL_DATA_HEADER))
		return;

	MLT_Packet::PKT_TUNNEL_DATA_HEADER *pHeader = (MLT_Packet::PKT_TUNNEL_DATA_HEADER *)pData;

	// QoS
	_ProcessIncomingPacketQoS(pHeader);

#ifdef RECORD_PACKET_HISTORY
	std::string logStr = std::to_string(int32_t(pHeader->TPSN));
	while(logStr.length() < 4)
		logStr = " " + logStr;
	logStr = "  << " + logStr + " " + std::to_string(pHeader->AckSNBase) + " " + std::to_string(pHeader->AckSNMask);
#endif

	switch (pHeader->dataType)
	{
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::AccessPoints:
		//_LOG("<< AccessPoints packet on tunnel " << GetTunnelId());
		if(dataLen >= offsetof(MLT_Packet::PKT_ADD_ACCESS_POINTS, accessPoints.AddressData))
		{
			const NodeAccessPoints &aps = ((MLT_Packet::PKT_ADD_ACCESS_POINTS*)pData)->accessPoints;
			if(dataLen == sizeof(MLT_Packet::PKT_TUNNEL_DATA_HEADER) + aps.GetSize())
			{
				CreateLinksFromAPs(aps);
			}
			else
			{
				_LOG_ERROR("Invalid AccessPoints packet on tunnel " << GetTunnelId());
			}
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::Close:
		Close(true, false);
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::MessageDataSlice:
		if(dataLen >= sizeof(MLT_Packet::PKT_MESSAGE_DATA_SLICE))
		{
			const MLT_Packet::PKT_MESSAGE_DATA_SLICE &dataSlice = *(MLT_Packet::PKT_MESSAGE_DATA_SLICE*)pData;
			uint16_t expectedSliceSize = uint16_t(std::min(dataSlice.msgTotalLen - dataSlice.sliceIdx * MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize, MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize));
			if(dataSlice.msgTotalLen > 0 && dataLen == offsetof(MLT_Packet::PKT_MESSAGE_DATA_SLICE, slice) + expectedSliceSize)
			{
				if(_previouslyReceivedMessages.find(dataSlice.msgId) != _previouslyReceivedMessages.end())		// the message was already previously received and somehow received again, immediately acknowledge it
				{
					_SendMessageAcknowledgePacket(dataSlice.msgId);
				}
				else
				{
					auto itor = _IncomingMessages.find(dataSlice.msgId);
					if(itor == _IncomingMessages.end())
						itor = _IncomingMessages.emplace(dataSlice.msgId, std::make_shared<MLT_IncomingMessage>(dataSlice.msgId, dataSlice.msgTotalLen)).first;
					if(itor->second->OnRecvMessageSlice(dataSlice.sliceIdx, dataSlice.slice, expectedSliceSize))
					{
						_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
						if(itor->second->IsDone())
						{
							_LOG("<< Tunnel MsgData " << dataSlice.msgId << ": dup " << itor->second->GetNumDuplicatedSlicesReceived() << " / total " << itor->second->GetTotalSlices());
							_CreateInfo.EventHandler->OnMessageReceived(itor->second->GetData(), itor->second->GetDataLen());
							if(itor->second->PullMessageAcknowledge())
							{
								if(!_SendMessageAcknowledgePacket(dataSlice.msgId))
									itor->second->OnMessageAcknowledgeLost();
							}
						}
					}
				}
				//_LOG("<< Tunnel MsgData " << ad.dataId << " " << ad.sliceIdx);

#ifdef RECORD_PACKET_HISTORY
				logStr += " MD msg(" + std::to_string(dataSlice.msgId) + ").slice(" + std::to_string(dataSlice.sliceIdx) + ")";
#endif
			}
			else
			{
				_LOG_ERROR("Invalid MessageData packet on tunnel " << GetTunnelId());
			}
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::MessageAcknowledge:
		if(dataLen == sizeof(MLT_Packet::PKT_MESSAGE_ACKNOWLEDGE))
		{
			const MLT_Packet::PKT_MESSAGE_ACKNOWLEDGE &ack = *(MLT_Packet::PKT_MESSAGE_ACKNOWLEDGE*)(pData);
			for(auto itor = _OutgoingMessages.begin(); itor != _OutgoingMessages.end(); itor++)
			{
				std::shared_ptr<MLT_OutgoingMessage> ptr = itor->second;
				if(ptr->GetId() == ack.msgId)
				{
					_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
					// no need to check ptr->IsDone() here, since IsDone() relies on QoS ack of the MessageDataSlice packets, which could arrive after the MessageAcknowledge packet.
					_LOG("message " << ack.msgId << " sent (" << uint64_t(os::Timestamp::Get()) - ptr->GetAddedTs() << " ms): " << ptr->GetTotalSlices() << " = " << ptr->GetTotalSent() << " - " << ptr->GetTotalLost());
					_CreateInfo.EventHandler->OnMessageSent((void *)ptr->GetCookie(), true);
					_OutgoingMessages.erase(itor);

					break;
				}
			}

#ifdef RECORD_PACKET_HISTORY
			logStr += " MA " + std::to_string(ack.msgId);
#endif
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::MessageReject:
		if(dataLen == sizeof(MLT_Packet::PKT_MESSAGE_REJECT))
		{
			const MLT_Packet::PKT_MESSAGE_REJECT &rej = *(MLT_Packet::PKT_MESSAGE_REJECT*)(pData);
			for(auto itor = _OutgoingMessages.begin(); itor != _OutgoingMessages.end(); itor++)
			{
				std::shared_ptr<MLT_OutgoingMessage> ptr = itor->second;
				if(ptr->GetId() == rej.msgId)
				{
					_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
					_LOG("message " << rej.msgId << " rejected by receiver.");
					_CreateInfo.EventHandler->OnMessageSent((void *)ptr->GetCookie(), false);
					_OutgoingMessages.erase(itor);

					break;
				}
			}

#ifdef RECORD_PACKET_HISTORY
			logStr += " MA " + std::to_string(rej.msgId);
#endif
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::Empty:
		// do nothing
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileRequestBlock:
		if(dataLen == sizeof(MLT_Packet::PKT_FILE_REQUEST_BLOCK))
		{
			const MLT_Packet::PKT_FILE_REQUEST_BLOCK &req = *(MLT_Packet::PKT_FILE_REQUEST_BLOCK*)(pData);
			_LOG("[MLT] receiving file block request id = " << req.fileId << ", block index = " << req.blockIdx << ", length = " << req.fileSize << ", priority = " << req.priority << ", hash = " << rt::tos::Base32CrockfordLowercaseOnStack<>(req.fileHash, 32));

#ifdef RECORD_PACKET_HISTORY
			logStr += " FR id = " + std::to_string(req.fileId) + ", size = " + std::to_string(req.fileSize) + ", block index = " + std::to_string(req.blockIdx) + ", priority = " + std::to_string(req.priority);
#endif

			std::shared_ptr<MLT_OutgoingFile> pOutgoingFile;
			auto itor = _OutgoingFiles.find(req.fileId);
			if(itor == _OutgoingFiles.end())
			{
				MLT_OutgoingFileReader *pReader = _CreateInfo.EventHandler->OnFileRequest(GetHandle(), *(MLT_FileHash*)&req.fileHash, req.fileSize);
				if(!pReader)
				{
					_SendFileRejectRequestPacket(req.fileId, req.blockIdx);
					break;
				}
				pOutgoingFile = std::make_shared<MLT_OutgoingFile>(*(MLT_FileHash*)&req.fileHash, req.fileSize, pReader, req.priority, req.fileId);
				_OutgoingFiles.emplace(req.fileId, pOutgoingFile);
			}
			else
				pOutgoingFile = itor->second;

			if(!pOutgoingFile || !pOutgoingFile->RequestBlock(req.blockIdx, req.sliceMask, sizeof(req.sliceMask)))
			{
				_SendFileRejectRequestPacket(req.fileId, req.blockIdx);
				break;
			}
			_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
			_LOG("[MLT] remaining slices in the file " << pOutgoingFile->GetNumRemainingSlices());
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileCancelRequest:
		if(dataLen == sizeof(MLT_Packet::PKT_FILE_CANCEL_REQUEST))
		{
			const MLT_Packet::PKT_FILE_CANCEL_REQUEST &req = *(MLT_Packet::PKT_FILE_CANCEL_REQUEST*)(pData);
			_LOG("[MLT] receiving file cancel request id = " << req.fileId);

#ifdef RECORD_PACKET_HISTORY
			logStr += " FC id = " + std::to_string(req.fileId);
#endif

			auto itor = _OutgoingFiles.find(req.fileId);
			if(itor != _OutgoingFiles.end())
			{
				_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
				_LOG("[MLT] file " << req.fileId << " canceled");
				_CreateInfo.EventHandler->OnFileUnrequest(GetHandle(), itor->second->GetFileReader());
				_OutgoingFiles.erase(itor);
			}
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileSlice:
		if(dataLen >= sizeof(MLT_Packet::PKT_FILE_SLICE))
		{
#ifdef RECORD_PACKET_HISTORY
			logStr += " FS file(" + std::to_string(dataSlice.fileId) + ").slice(" + std::to_string(dataSlice.sliceIdx) + ")";
#endif
			const MLT_Packet::PKT_FILE_SLICE &dataSlice = *(MLT_Packet::PKT_FILE_SLICE*)pData;
			uint16_t sliceSize = dataLen - offsetof(MLT_Packet::PKT_FILE_SLICE, slice);
			if(_previouslyReceivedFiles.find(dataSlice.fileId) != _previouslyReceivedFiles.end())		// the message was already previously received and somehow received again, immediately acknowledge it
			{
				_SendFileAcknowledgePacket(dataSlice.fileId);
			}
			else
			{
				auto itor = _IncomingFiles.find(dataSlice.fileId);
				if(itor == _IncomingFiles.end())
				{
					_LOG("[MLT] FileSlice packet " << dataSlice.sliceIdx << " for unknown id " << dataSlice.fileId << " received");
					_SendFileCancelRequestPacket(dataSlice.fileId);
					break;
				}
				if(itor->second->OnRecvFileSlice(dataSlice.sliceIdx, dataSlice.slice, sliceSize))
				{
					_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
					if(itor->second->IsDone())
					{
						_LOG("<< Tunnel received file " << dataSlice.fileId); // << ": dup " << itor->second->GetNumDuplicatedSlicesReceived() << " / total " << itor->second->GetTotalSlices());
						if(itor->second->PullFileAcknowledge())
						{
							if(!_SendFileAcknowledgePacket(dataSlice.fileId))
								itor->second->OnFileAcknowledgeLost();
						}
					}
				}
				else
				{
					//_LOG("!!!!!!!!!!!!!!!!!! OnRecvFileSlice returns false !!!!!!!!!!!!!!!!!");
					MLT_IncomingFile::Error err = itor->second->GetLastError();
					if(err != MLT_IncomingFile::E_NoError)
					{
						_LOG("[MLT] file " << dataSlice.fileId << " download got an error. Disk possibly full?");
						MLT_FileHash fileHash = itor->second->GetFileHash();
						_IncomingFiles.erase(itor);
						_CreateInfo.EventHandler->OnFileDownloadInterrupted(GetHandle(), fileHash, err == MLT_IncomingFile::E_CorruptedControlData ? MLT_TunnelEventHandler::FDI_LocalControlDataError : MLT_TunnelEventHandler::FDI_LocalWriteError);
					}
				}
			}
			//_LOG("<< Tunnel MsgData " << ad.dataId << " " << ad.sliceIdx);
		}
		else
		{
			_LOG_ERROR("Invalid FileSlice packet on tunnel " << GetTunnelId());
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileAcknowledge:
		if(dataLen == sizeof(MLT_Packet::PKT_FILE_ACKNOWLEDGE))
		{
			const MLT_Packet::PKT_FILE_ACKNOWLEDGE &ack = *(MLT_Packet::PKT_FILE_ACKNOWLEDGE*)(pData);
#ifdef RECORD_PACKET_HISTORY
			logStr += " FA " + std::to_string(ack.fileId);
#endif
			auto itor = _OutgoingFiles.find(ack.fileId);
			if(itor != _OutgoingFiles.end())
			{
				_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
				_LOG("[MLT] file " << ack.fileId << " acknowledged" << ", pulls = " << itor->second->GetNumPullSlice() << ", acks = " << itor->second->GetNumAcks() << ", losts = " << itor->second->GetNumLosts() << ", pending = " << itor->second->GetNumPendingAckSlices());
				_CreateInfo.EventHandler->OnFileUnrequest(GetHandle(), itor->second->GetFileReader());
				_OutgoingFiles.erase(itor);
			}
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileRejectRequest:
		if(dataLen == sizeof(MLT_Packet::PKT_FILE_REJECT_REQUEST))
		{
			const MLT_Packet::PKT_FILE_REJECT_REQUEST &rej = *(MLT_Packet::PKT_FILE_REJECT_REQUEST*)(pData);
#ifdef RECORD_PACKET_HISTORY
			logStr += " FJ " + std::to_string(rej.fileId);
#endif
			auto itor = _IncomingFiles.find(rej.fileId);
			if(itor != _IncomingFiles.end())
			{
				_NoTaskProgressSince = uint64_t(os::Timestamp::Get());
				_LOG("[MLT] file " << rej.fileId << " download request rejected");
				MLT_FileHash fileHash = itor->second->GetFileHash();
				_IncomingFiles.erase(itor);
				_CreateInfo.EventHandler->OnFileDownloadInterrupted(GetHandle(), fileHash, MLT_TunnelEventHandler::FDI_Rejected);
			}
		}
		break;
	case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::BatchAck:
		if(dataLen >= sizeof(MLT_Packet::PKT_BATCH_ACK))
		{
			const MLT_Packet::PKT_BATCH_ACK &acks = *(MLT_Packet::PKT_BATCH_ACK*)(pData);
			if(MLT_Packet::PKT_BATCH_ACK::GetSize(acks.SNBegin, acks.SNEnd) == dataLen)
			{
				uint32_t mergeBegin = acks.SNBegin;									// begin of merge range, inclusive
				//mergeBegin = std::max(mergeBegin, _NextAckCheckSN);		// mergeBegin should NOT be clamped to _NextAckCheckSN, packets with acks coming too late are also essential for RTT calculation
				if(mergeBegin + _SendWindowBufferSize < _NextSendSN)		// However, it should be not too far from _NextSendSN, otherwise the corresponding _SentPacketTime is already overwritten by older packets
					mergeBegin = _NextSendSN - _SendWindowBufferSize;
				uint32_t mergeEnd = std::min(acks.SNEnd + 1, _NextSendSN);			// end of merge range, not inclusive
				uint32_t ackBase = acks.SNBegin - acks.SNBegin % 64;
				uint64_t curTime = uint64_t(os::Timestamp::Get());
#ifdef ACK_DEBUG
				std::string ackString = "  <<";
#endif
				{
					uint32_t idx = acks.firstUnackedPacketSN % _SendWindowBufferSize;
					if(acks.firstUnackedPacketSN < _NextSendSN && acks.firstUnackedPacketSN + _SendWindowBufferSize >= _NextSendSN && !_SentPacketAcked[idx])
					{
						uint32_t curTimeOffset = uint32_t(curTime - _TunnelCreationTime);
						if(curTimeOffset >= _SentPacketTime[idx])
							_UpdateRTT(curTimeOffset - _SentPacketTime[idx]);
					}
				}
				for(uint32_t i = mergeBegin; i < mergeEnd; i++)
				{
					if(acks.AckMask[(i - ackBase) / 64] & (1ull << ((i - ackBase) % 64)))
					{
						uint32_t idx = i % _SendWindowBufferSize;
						if(!_SentPacketAcked[idx])
						{
#ifdef ACK_DEBUG
							ackString += " " + std::to_string(i);
#endif
							_SentPacketAcked[idx] = true;
							_SentPacketAckTime[idx] = uint32_t(curTime - _TunnelCreationTime);
							if(i == acks.firstUnackedPacketSN)
							{
								if(_SentPacketAckTime[idx] >= _SentPacketTime[idx] + acks.firstUnackedPacketAckDelay)
								{
									_PacketLatencyRecentHistory.AddData(curTime / 1000, _SentPacketAckTime[idx] - _SentPacketTime[idx]);
									_PacketLatencyEntryCountRecentHistory.AddData(curTime / 1000, 1);
									//_UpdateRTT(_SentPacketAckTime[idx] - _SentPacketTime[idx] - acks.firstUnackedPacketAckDelay);
									//_LOG("Ack " << _NextAckCheckSN << ": SRTT = " << _SRTT << ", DevRTT = " << _DevRTT << ", RTO = " << _RTO);
								}
							}
							else if(i == acks.lastUnackedPacketSN)
							{
								if(_SentPacketAckTime[idx] >= _SentPacketTime[idx] + acks.lastUnackedPacketAckDelay)
								{
									_PacketLatencyRecentHistory.AddData(curTime / 1000, _SentPacketAckTime[idx] - _SentPacketTime[idx]);
									_PacketLatencyEntryCountRecentHistory.AddData(curTime / 1000, 1);
									//_UpdateRTT(_SentPacketAckTime[idx] - _SentPacketTime[idx] - acks.lastUnackedPacketAckDelay);
									//_LOG("Ack " << _NextAckCheckSN << ": SRTT = " << _SRTT << ", DevRTT = " << _DevRTT << ", RTO = " << _RTO);
								}
							}
						}
					}
				}
				//_LOG(acks.firstUnackedPacketAckDelay << " " << acks.lastUnackedPacketAckDelay);
#ifdef ACK_DEBUG
				if(ackString.size() > 4)
					AckDebugLog(GetTunnelId(), ackString.c_str());
#endif
			}
		}
	}

	_PerformNextAckCheck(false, false);
	if(_NumUnackedPackets != 0)
	{
		_SendBatchAckPacket(false);
	}

#ifdef RECORD_PACKET_HISTORY
	_Log.push_back(logStr);
#endif

}

void MLT_Tunnel::_UpdateRTT(uint32_t newRTTSample)
{
	constexpr static uint32_t mu = 1, delta = 4;
	if(_SRTT == 0)
	{
		_SRTT = newRTTSample;
		_DevRTT = newRTTSample / 2;
	}
	else
	{
		uint32_t newDevRTT = uint32_t(abs(int32_t(newRTTSample) - int32_t(_SRTT)));
		_DevRTT = (3 * _DevRTT + newDevRTT) / 4;
		_SRTT = (7 * _SRTT + newRTTSample) / 8;
	}
	_RTO = mu * _SRTT + delta * _DevRTT;
}

void MLT_Tunnel::_PerformNextAckCheck(bool bForcePopFront, bool bForcePopAll)
{
	EnterCSBlock(_CS);

	uint32_t checkUpTo = _NextSendSN;
	while(_NextAckCheckSN < checkUpTo)
	{
		uint64_t curTime = uint64_t(os::Timestamp::Get());
		uint32_t curTimeOffset = curTime - _TunnelCreationTime;
		uint32_t idx = _NextAckCheckSN % _SendWindowBufferSize;
		bool bAcked;
		if(_SentPacketAcked[idx])
		{
			bAcked = true;
			_MaxAckedSN = _NextAckCheckSN;
		}
		else if(_SentPacketTime[idx] + _RTO < curTimeOffset || bForcePopFront || bForcePopAll)
			bAcked = false;
		else
			break;

		if(bAcked)
		{
			_PacketAckedRecentHistory.AddData(curTime / 1000, 1);
		}
		else
		{
			_PacketLostRecentHistory.AddData(curTime / 1000, 1);
			//_UpdateRTT(_RTO + 8);		// use RTO + 8 to force SRTT to increase at least one
			//_LOG("Loss " << _NextAckCheckSN << ": SRTT = " << _SRTT << ", DevRTT = " << _DevRTT << ", RTO = " << _RTO);
		}

#ifdef RECORD_PACKET_HISTORY
		_PacketAckHistory.push_back(bAcked);
#endif

		if(_SentPacketTaskId[idx] >= uint32_t(MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::Max))		// regular tasks
		{
			auto itorF = _OutgoingFiles.find(_SentPacketTaskId[idx]);
			if(itorF != _OutgoingFiles.end())
			{
				std::shared_ptr<MLT_OutgoingFile> ptr = itorF->second;
				if(bAcked)
				{
					ptr->OnFileSliceAcked(_SentPacketCustomData[idx]);
					_NoTaskProgressSince = curTime;
				}
				else
					ptr->OnFileSliceLost(_SentPacketCustomData[idx]);
			}
			else
			{
				//_LOG("Tunnel packet ACK: " << GetTunnelId() << " " << _NextAckCheckSN << ": " << _SentPacketTaskId[idx] << " " << _SentPacketCustomData[idx]);
				for(auto itor = _OutgoingMessages.begin(); itor != _OutgoingMessages.end(); itor++)
				{
					std::shared_ptr<MLT_OutgoingMessage> ptr = itor->second;
					if(ptr->GetId() == _SentPacketTaskId[idx])
					{
						if(bAcked)
						{
							ptr->OnSliceAcked(_SentPacketCustomData[idx]);
							_NoTaskProgressSince = curTime;
						}
						else
							ptr->OnSliceLost(_SentPacketCustomData[idx]);
						break;
					}
				}
			}
		}
		else		// control messages
		{
			MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType type = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType(_SentPacketTaskId[idx]);
			switch (type)
			{
			case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::MessageAcknowledge:
			{
				uint32_t msgId = _SentPacketCustomData[idx];
				if(_previouslyReceivedMessages.find(msgId) != _previouslyReceivedMessages.end())
				{
					if(!bAcked)
						_SendMessageAcknowledgePacket(msgId);
					else
						_NoTaskProgressSince = curTime;

				}
				else
				{
					auto itor = _IncomingMessages.find(msgId);
					if(itor != _IncomingMessages.end())
					{
						if(itor->second->IsDone())
						{
							if(bAcked)
							{
								_previouslyReceivedMessages.insert(itor->second->GetId());		// do this before erasing the itor
								_IncomingMessages.erase(itor);
								_NoTaskProgressSince = curTime;
							}
							else
								itor->second->OnMessageAcknowledgeLost();
						}
						else
						{
							_LOG("[MLT] BUG!!! MessageAcknowledge packet for incoming message " << msgId << " was sent and " << (bAcked ? "acked" : "lost") << " but the received message is not complete yet.");
						}
					}
					else
					{
						_LOG("[MLT] BUG!!! MessageAcknowledge packet for incoming message " << msgId << " was sent and " << (bAcked ? "acked" : "lost") << " but the message doesn't exist.");
					}
				}
				break;
			}
			case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileRequestBlock:
			{
				uint32_t fileId = _SentPacketCustomData[idx];
				auto itor = _IncomingFiles.find(fileId);
				if(itor != _IncomingFiles.end())
				{
					if(!bAcked)
						itor->second->OnBlockRequestLost();
					else
						_NoTaskProgressSince = curTime;
				}
				break;
			}
			case MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileAcknowledge:
			{
				uint32_t fileId = _SentPacketCustomData[idx];
				if(_previouslyReceivedFiles.find(fileId) != _previouslyReceivedFiles.end())
				{
					if(!bAcked)
						_SendFileAcknowledgePacket(fileId);
					else
						_NoTaskProgressSince = curTime;
				}
				else
				{
					auto itor = _IncomingFiles.find(fileId);
					if(itor != _IncomingFiles.end())
					{
						if(itor->second->IsDone())
						{
							if(bAcked)
							{
								_previouslyReceivedFiles.insert(itor->second->GetId());
								MLT_FileHash fileHash = itor->second->GetFileHash();
								itor->second->FinalizeWriter();
								_IncomingFiles.erase(itor);		// erase after all the above calls
								_CreateInfo.EventHandler->OnFileDownloaded(GetHandle(), fileHash);
								_NoTaskProgressSince = curTime;
							}
							else
								itor->second->OnFileAcknowledgeLost();
						}
						else
						{
							_LOG("[MLT] BUG!!! FileAcknowledge packet for incoming file " << fileId << " was sent and " << (bAcked ? "acked" : "lost") << " but the received file is not complete yet.");
						}
					}
					else
					{
						_LOG("[MLT] BUG!!! FileAcknowledge packet for incoming file " << fileId << " was sent and " << (bAcked ? "acked" : "lost") << " but the file doesn't exist.");
					}
				}
				break;
			}
			default:
				break;
			}
		}

		bForcePopFront = false;		// bForcePopFront only force pops the first element at front
		_NextAckCheckSN++;
	}

	_SendQueuedData();
}

// Be careful that this function doesn't define a strict order, if both links are direct / not direct and have the same latency, it prefers B
// Therefore do not use it in something like a quick-sort, the result would be not well defined.
bool PreferLinkA(const std::shared_ptr<MLT_Link>& linkA, const std::shared_ptr<MLT_Link>& linkB)
{
	if(linkA == nullptr)
		return false;
	if(linkB == nullptr)
		return true;

	// if one is direct link and the other isn't
	if(linkA->IsDirectLink() != !linkB->IsDirectLink())
		return linkA->IsDirectLink();			// prefer the direct one

	// prefer lower latency
	return linkA->GetLatency() < linkB->GetLatency();
}

bool MLT_Tunnel::_SendTunnelData(MLT_Packet::PKT_TUNNEL_DATA_HEADER* pHeaderAndData, uint16_t totalLen, bool bWithSN, bool bOverAllLinks, uint32_t taskId, uint32_t msgCustomData)
{
	EnterCSBlock(_CS);

	// first check if this packet would overflow the send window, if so, make room for it by forcing the oldest entry out
	//if(_NextSendSN - _NextAckCheckSN >= _SendWindowCurSize)
	//	_PerformNextAckCheck(true, false);

	if(bWithSN)
		pHeaderAndData->TPSN = _NextSendSN;
	else
		pHeaderAndData->TPSN = 0xffffffff;

	pHeaderAndData->WaitingAckSN = _NextAckCheckSN;

#ifdef ACK_DEBUG
	if(pHeaderAndData->dataType == MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::FileSlice)
	{
		const MLT_Packet::PKT_FILE_SLICE& dataSlice = *(MLT_Packet::PKT_FILE_SLICE*)pHeaderAndData;
		std::string str = " >   " + std::to_string(pHeaderAndData->TPSN) + "(slice " + std::to_string(dataSlice.sliceIdx) + ")";
		AckDebugLog(GetTunnelId(), str.c_str());
	}
#endif

	bool ret = false;

	if(bOverAllLinks)
	{
		for(auto& itor : _ConnectedLinkIds)
		{
			auto itor2 = _IdToLinks.find(itor);
			if(itor2 != _IdToLinks.end())
				ret = ret || itor2->second->SendPacket((uint8_t*)pHeaderAndData, totalLen, true, false);
		}
	}
	else
	{
		std::shared_ptr<MLT_Link> candidateLink;
		for(auto& itor : _ConnectedLinkIds)
		{
			auto itor2 = _IdToLinks.find(itor);
			if(itor2 != _IdToLinks.end() && PreferLinkA(itor2->second, candidateLink))
				candidateLink = itor2->second;
		}
		if(candidateLink != nullptr)
			ret = candidateLink->SendPacket((uint8_t*)pHeaderAndData, totalLen, true, false);
	}

	if(bWithSN && ret)
	{
		uint32_t idx = _NextSendSN % _SendWindowBufferSize;
		_SentPacketAcked[idx] = false;
		_SentPacketTaskId[idx] = taskId;
		_SentPacketCustomData[idx] = msgCustomData;
		_SentPacketTime[idx] = uint32_t(os::Timestamp::Get() - _TunnelCreationTime);
		_SentPacketAckTime[idx] = 0xffffffffu;
		_NextSendSN++;
	}

	return ret;
}

void MLT_Tunnel::_SendCloseTunnelPacket()
{
	EnterCSBlock(_CS);

	MLT_Packet::PKT_TUNNEL_DATA_HEADER header;
	header.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::Close;

	_SendTunnelData(&header, sizeof(header), false, true, uint32_t(header.dataType), 0);
}

void MLT_Tunnel::_SendAccessPointsPacket()
{
	EnterCSBlock(_CS);

	MLT_Packet::PKT_ADD_ACCESS_POINTS packet;
	_pCore->GetNodeAccessPoints(packet.accessPoints);
	if(packet.accessPoints.GetSize() > 0)
	{
		packet.dataType = MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::AccessPoints;
		_SendTunnelData(&packet, uint16_t(offsetof(MLT_Packet::PKT_ADD_ACCESS_POINTS, accessPoints) + packet.accessPoints.GetSize()), true, true, uint32_t(packet.dataType), 0);
		_LastAccessPointPacketTs = uint64_t(os::Timestamp::Get());

		//_LOG(">> AccessPoints packet on tunnel " << GetTunnelId());
	}
}

void MLT_Tunnel::Close(bool bClosedByDestination, bool bNotifyDestination)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return;

	// process all acks that aren't processed yet
	_PerformNextAckCheck(true, true);

	if(bNotifyDestination)
		_SendCloseTunnelPacket();

	for(auto& linkId : _ConnectedLinkIds)
	{
		auto itor = _IdToLinks.find(linkId);
		if(itor != _IdToLinks.end())
		{
			std::shared_ptr<MLT_Link> pLink = itor->second;
			if(pLink->OnceConnected())
				_AddBackupLink(pLink);
		}
	}

	_ConnectedLinkIds.clear();
	_IdToLinks.clear();
	_AddrToLinks.clear();

	if(_Status == Status::Connected)
		_CreateInfo.EventHandler->OnDisconnected(GetHandle(), bClosedByDestination);

	if(_OutgoingMessages.size())
	{
		for(auto &itor : _OutgoingMessages)
		{
			std::shared_ptr<MLT_OutgoingMessage> ptr = itor.second;
			_CreateInfo.EventHandler->OnMessageSent((void *)ptr->GetCookie(), false);
		}
		_OutgoingMessages.clear();
	}

	for(auto& itor : _OutgoingFiles)
	{
		_CreateInfo.EventHandler->OnFileUnrequest(GetHandle(), itor.second->GetFileReader());
	}
	_OutgoingFiles.clear();

	for(auto& itor : _IncomingFiles)
	{
		_CreateInfo.EventHandler->OnFileDownloadInterrupted(GetHandle(), itor.second->GetFileHash(), MLT_TunnelEventHandler::FDI_TunnelClose);
	}
	_IncomingFiles.clear();

	_Status = Status::Closed;
}

void MLT_Tunnel::_OnLinkConnect(uint32_t linkId)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return;

	auto itor = _IdToLinks.find(linkId);
	if(itor == _IdToLinks.end())
		return;

	if(_ConnectedLinkIds.find(linkId) == _ConnectedLinkIds.end())
	{
		_ConnectedLinkIds.insert(linkId);

		_CreateInfo.EventHandler->OnLinkConnected(GetHandle(), itor->second->GetDestinationAddress(), itor->second->GetBouncerAddress());

		if(_ConnectedLinkIds.size() == 1)
		{
			_Status = Status::Connected;
			_CreateInfo.EventHandler->OnConnected(GetHandle());
		}
	}
}

void MLT_Tunnel::_OnLinkDisconnect(uint32_t linkId)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return;

	auto itor = _IdToLinks.find(linkId);
	if(itor != _IdToLinks.end())
	{
		std::shared_ptr<MLT_Link> pLink = itor->second;
		if(pLink->OnceConnected())
		{
			_AddBackupLink(pLink);
			if(pLink->IsDirectLink())
				_LOG_WARNING("[MLT] Tunnel " << GetTunnelId() << " direct link disconnected!");
		}
	}

	_RemoveLink(linkId);
	//_LOG("[MLT] Removing disconnected link " << linkId << " of tunnel " << GetTunnelId());
	if(_ConnectedLinkIds.size() == 0 && _Status == Status::Connected)
	{
		_Status = Status::Disconnected;
		_ResetFlags();
		_CreateInfo.EventHandler->OnDisconnected(GetHandle(), false);
		for(auto &fileDownload : _IncomingFiles)
			_CreateInfo.EventHandler->OnFileDownloadInterrupted(GetHandle(), fileDownload.second->GetFileHash(), MLT_TunnelEventHandler::FDI_TunnelDisconnect);

	}
}

void MLT_Tunnel::_RemoveLink(uint32_t linkId)
{
	EnterCSBlock(_CS);

	auto itor = _IdToLinks.find(linkId);
	if(itor != _IdToLinks.end())
	{
		std::shared_ptr<MLT_Link> pLink = itor->second;

		auto itor2 = _ConnectedLinkIds.find(linkId);
		if(itor2 != _ConnectedLinkIds.end())
		{
			_ConnectedLinkIds.erase(linkId);
			_CreateInfo.EventHandler->OnLinkDisconnected(GetHandle(), pLink->GetDestinationAddress(), pLink->GetBouncerAddress());
		}

		_AddrToLinks.erase(pLink->GetLinkAddress());
		_PendingDeleteLinkIds.emplace(linkId);
	}
}

void MLT_Tunnel::_AddBackupLink(std::shared_ptr<MLT_Link> pLink)
{
	if(pLink->IsDirectLink())
	{
		if(std::find(_backupDirectLinkDestinations.begin(), _backupDirectLinkDestinations.end(), pLink->GetDestinationAddress()) == _backupDirectLinkDestinations.end())
		{
			_backupDirectLinkDestinations.push_back(pLink->GetDestinationAddress());
			if(_backupDirectLinkDestinations.size() > 4)
				_backupDirectLinkDestinations.pop_front();
		}
	}
	else
	{
		if(std::find(_backupBouncerLinkDestinations.begin(), _backupBouncerLinkDestinations.end(), std::make_pair(*pLink->GetBouncerAddress(), pLink->GetDestinationAddress())) == _backupBouncerLinkDestinations.end())
		{
			_backupBouncerLinkDestinations.push_back({ *pLink->GetBouncerAddress(), pLink->GetDestinationAddress() });
			if(_backupBouncerLinkDestinations.size() > 4)
				_backupBouncerLinkDestinations.pop_front();
		}
	}
}

void MLT_Tunnel::PrintStatus()
{
	EnterCSBlock(_CS);

	uint64_t curTime = uint64_t(os::Timestamp::Get());

	const static char status[][15] = { "Disconnected", "Connected", "Closed" };
	uint32_t destTunnelId = GetDestinationTunnelId();
	_LOG(GetTunnelId() << " <---> " << (destTunnelId == 0xffffffff ? rt::String_Ref("?") : rt::tos::Number(destTunnelId)) << " (" << status[uint16_t(GetStatus())] << "): " << GetTunnelUID() << ", dest device: " << tos(GetDestinationDHTAddress()));
	_LOG("Packet serial number (sent (acked) <-> recv): " << int32_t(_NextSendSN) - 1 << "(" << _MaxAckedSN << ")" << " <-> " << _RecvSNLargest);
	_LOG("Session id (local <-> destination): " << _SessionId << " <-> " << _DestinationSessionId);
	_LOG("SRTT = " << _SRTT << ", DevRTT = " << _DevRTT << ", RTO = " << _RTO);
	_LOG("Send buffer: range = [" << _NextAckCheckSN << ", " << _NextSendSN << ") (" << _NextSendSN - _NextAckCheckSN << "), age range = [-" << (_NextSendSN > _NextAckCheckSN ? curTime - _TunnelCreationTime - _SentPacketTime[_NextAckCheckSN % _SendWindowBufferSize] : 0)
		<< ", -" << (_NextSendSN > _NextAckCheckSN ? curTime - _TunnelCreationTime - _SentPacketTime[(_NextSendSN - 1) % _SendWindowBufferSize] : 0) << "]");
	_LOG("Recv buffer: range = [" << _RecvSNWaitingSmallest << ", " << _RecvSNLargest << "] (" << _RecvSNLargest - _RecvSNWaitingSmallest << "), age range = [-" << curTime - _FirstUnackedPacketRecvTime << ", -" << curTime - _LastUnackedPacketRecvTime << "]");
	uint64_t idleTime, taskIdleTime;
	GetIdleTime(idleTime, taskIdleTime);
	_LOG("No task: " << idleTime << "ms, Task stuck: " << taskIdleTime << "ms");

	_LOG(_IdToLinks.size() << " Links:");
	for(auto &itor : _IdToLinks)
		_LOG("  " << itor.second->GetStatusString());

	_LOG(_OutgoingMessages.size() << " outgoing messages:");
	for(auto &itor : _OutgoingMessages)
	{
		std::shared_ptr<MLT_OutgoingMessage> ptr = itor.second;
		uint32_t completion = uint32_t(double(ptr->GetTotalSent() - ptr->GetTotalLost() - ptr->GetPending()) * 100 / ptr->GetTotalSlices());
		uint32_t dropRate = uint32_t(double(ptr->GetTotalLost()) * 100 / (ptr->GetTotalSent() - ptr->GetPending()));
		_LOG("  " << ptr->GetId() << ": " << ptr->GetTotalLen() << " (" << completion << "%), drop rate " << dropRate << "% (" << ptr->GetTotalLost() << " / " << ptr->GetTotalSent() - ptr->GetPending() << ")");
	}
	_LOG(_IncomingMessages.size() << " incoming messages:");
	for(auto &itor : _IncomingMessages)
	{
		std::shared_ptr<MLT_IncomingMessage> ptr = itor.second;
		uint32_t completion = uint32_t(double(ptr->GetNumUniqueSlicesReceived()) * 100 / ptr->GetTotalSlices());
		_LOG("  " << ptr->GetId() << ": " << ptr->GetTotalLen() << " (" << completion << "%), dup " << ptr->GetNumDuplicatedSlicesReceived() << " / unique " << ptr->GetNumUniqueSlicesReceived());
	}
	_LOG(_IncomingFiles.size() << " incoming files:");
	for(auto &itor : _IncomingFiles)
	{
		std::shared_ptr<MLT_IncomingFile> ptr = itor.second;
		uint32_t completion = uint32_t(double(ptr->GetDownloadedSize()) * 100 / ptr->GetFileSize());
		_LOG("  " << ptr->GetId() << ": " << ptr->GetFileSize() << " (" << completion << "%), at " << ptr->GetDownloadSpeed() / 1024 << "KB/s"
			<< ", curBlock : " << ptr->GetCurBlockIdx() << " (" << ptr->GetNumRemainingSlicesInCurBlock() << " slices left " << ptr->GetFirstRemainingSliceInCurBlcok() << "), request sent : " << (ptr->GetCurBlockRequestSent() ? "true" : "false"));
	}
	_LOG(_OutgoingFiles.size() << " outgoing files:");
	for(auto& itor : _OutgoingFiles)
	{
		std::shared_ptr<MLT_OutgoingFile> ptr = itor.second;
		_LOG("  " << ptr->GetId() << ": " << ptr->GetFileSize() << ", curBlock : " << ptr->GetRequestedBlockIndex() << " (" << ptr->GetNumRemainingSlices() << " slices left, " << ptr->GetNumPendingAckSlices() << " slices pending ack)");
	}
}

bool MLT_Tunnel::QueueMessageSend(const uint8_t *pData, uint32_t dataLen, void *pCookie, uint32_t priority)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
		return false;

	_LOG("[MLT] Tunnel " << GetTunnelId() << " queuing message with id " << _NextOutgoingTaskId);
	_OutgoingMessages.emplace(priority, std::make_shared<MLT_OutgoingMessage>(pData, dataLen, pCookie, priority, _NextOutgoingTaskId++));

	_SendQueuedMessages();

	return true;
}

uint32_t MLT_Tunnel::QueueFileDownload(const MLT_FileHash &fileHash, uint64_t fileSize, MLT_IncomingFileWriter *pWriter, uint32_t priority)
{
	EnterCSBlock(_CS);

	if(_Status == Status::Closed)
	{
		pWriter->Release();
		return 0xffffffffu;
	}

	_LOG("[MLT] Tunnel " << GetTunnelId() << " queuing file download with id " << _NextOutgoingTaskId << " (hash " << rt::tos::Base32CrockfordLowercaseOnStack<>(fileHash) << ")");
	uint32_t fileId = _NextOutgoingTaskId++;
	std::shared_ptr<MLT_IncomingFile> ptr = std::make_shared<MLT_IncomingFile>(fileHash, fileSize, pWriter, priority, fileId);

	MLT_IncomingFile::Error err = ptr->GetLastError();
	if(err != MLT_IncomingFile::E_NoError)
	{
		ptr.reset();
		_CreateInfo.EventHandler->OnFileDownloadInterrupted(GetHandle(), fileHash, err == MLT_IncomingFile::E_CorruptedControlData ? MLT_TunnelEventHandler::FDI_LocalControlDataError : MLT_TunnelEventHandler::FDI_LocalWriteError);
		_LOG("[MLT] File download could not be started.");
		return 0xffffffffu;
	}

	// this might happen is the file is already fully downloaded before
	if(ptr->IsDone())
	{
		pWriter->FinalizeWrite();
		ptr.reset();
		_CreateInfo.EventHandler->OnFileDownloaded(GetHandle(), fileHash);
		_LOG("[MLT] File download completed immediately.");
		return 0xffffffffu;
	}

	_IncomingFiles.emplace(fileId, ptr);

	_SendFileRequests();

	return fileId;
}

bool MLT_Tunnel::StopFileDownload(uint32_t fileId)
{
	EnterCSBlock(_CS);

	auto itor = _IncomingFiles.find(fileId);
	if(itor != _IncomingFiles.end())
	{
		_SendFileCancelRequestPacket(itor->second->GetId());
		MLT_FileHash fileHash = itor->second->GetFileHash();
		_IncomingFiles.erase(itor);
		_CreateInfo.EventHandler->OnFileDownloadInterrupted(GetHandle(), fileHash, MLT_TunnelEventHandler::FDI_Cancelled);
		return true;
	}

	return false;
}

bool MLT_Tunnel::GetDownloadStatus(uint32_t fileId, MLT_FileDownloadStatus &outStatus)
{
	EnterCSBlock(_CS);

	auto itor = _IncomingFiles.find(fileId);
	if(itor == _IncomingFiles.end())
		return false;

	outStatus.fileHash = itor->second->GetFileHash();
	outStatus.fileSize = itor->second->GetFileSize();
	outStatus.downloadedSize = itor->second->GetDownloadedSize();
	outStatus.downloadSpeed = itor->second->GetDownloadSpeed();

	return true;
}

void MLT_Tunnel::StopFileServing(MLT_OutgoingFileReader *pReader)
{
	EnterCSBlock(_CS);
	for(auto &itor : _OutgoingFiles)
	{
		if(itor.second->GetFileReader() == pReader)
		{
			_SendFileRejectRequestPacket(itor.second->GetId(), itor.second->GetRequestedBlockIndex());
			_CreateInfo.EventHandler->OnFileUnrequest(GetHandle(), pReader);
			_OutgoingFiles.erase(itor.first);
			break;
		}
	}
}

void MLT_Tunnel::GetIdleTime(uint64_t &noTaskTime, uint64_t &noTaskProgressTime) const
{
	uint64_t curTime = uint64_t(os::Timestamp::Get());
	noTaskTime = _NoTaskSince == 0 ? 0 : curTime - _NoTaskSince;
	noTaskProgressTime = curTime - _NoTaskProgressSince;
}

void MLT_Tunnel::Awaken()
{
	EnterCSBlock(_CS);
	if(_Status == Status::Closed)
	{
		_ResetFlags();
		_LOG("[MLT] Closed -> Disconnected");
		_Status = Status::Disconnected;
	}
}

void MLT_Tunnel::DumpLog()
{
	EnterCSBlock(_CS);

	FILE *fp = fopen(("tunnel" + std::to_string(GetTunnelId()) + ".txt").c_str(), "w");
	for(auto &ele : _Log)
	{
		fprintf(fp, "%s\n", ele.c_str());
	}

	constexpr uint32_t columnWidth = 128;
	for(uint32_t i = 0; i < uint32_t(_PacketAckHistory.size()); i++)
	{
		fprintf(fp, _PacketAckHistory[i] ? "*" : " ");
		if(i % columnWidth == columnWidth - 1)
			fprintf(fp, " %d\n", i / columnWidth * columnWidth);
	}
	if(_PacketAckHistory.size() % columnWidth != 0)
	{
		for(uint32_t i = 0; i < columnWidth - uint32_t(_PacketAckHistory.size()) % columnWidth; i++)
			fprintf(fp, " ");
		fprintf(fp, " %d\n", uint32_t(_PacketAckHistory.size()) / columnWidth * columnWidth);
	}

	fclose(fp);
}

void MLT_Tunnel::GetCreateInfo(MLT_TunnelCreateInfo &outInfo) const
{
	memcpy(&outInfo, &_CreateInfo, sizeof(MLT_TunnelCreateInfo));
}

bool MLT_Tunnel::IsBusy()
{
	EnterCSBlock(_CS);

	return _Status == Status::Connected && _OutgoingFiles.size() + _IncomingFiles.size() + _OutgoingMessages.size() + _IncomingMessages.size() > 0;
}

void MLT_Tunnel::GetTunnelLatencyAndPacketLossRate(uint32_t range, uint32_t &latencyInMs, uint32_t &lossRateInPercentage_100x) const
{
	EnterCSBlock(_CS);

	range = std::max(range, 1U);

	latencyInMs = _SRTT;

	uint64_t curTime = uint64_t(os::Timestamp::Get());
	uint64_t totalLoss = _PacketLostRecentHistory.GetTotalValue(curTime / 1000, range);
	uint64_t totalAck = _PacketAckedRecentHistory.GetTotalValue(curTime / 1000, range);
	if(totalAck + totalLoss == 0)
		lossRateInPercentage_100x = 0;
	else
		lossRateInPercentage_100x = totalLoss * 10000 / (totalAck + totalLoss);
}

} // namespace upw
