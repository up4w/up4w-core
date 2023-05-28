#include "../netsvc_core.h"

#include "mlt_tunnel.h"
#include "mlt_packet_outgoing.h"
#include "mlt_link.h"

#pragma warning(error:4334)


namespace upw
{

MLT_Link::MLT_Link(const NetworkAddress &destinationAddr, const NetworkAddress *bouncerAddr, MLT_Tunnel *pTunnel, uint32_t linkId)
	: _pTunnel(pTunnel)
	, _LinkId(linkId)
	, _DestinationAddress(destinationAddr)
	, _bDirectLink(bouncerAddr == nullptr)
	, _BouncerAddress(bouncerAddr ? *bouncerAddr : NetworkAddress())
{
}

bool MLT_Link::SendPacket(uint8_t *pTunnelData, uint16_t tunnelDataLen, bool bWithSN, bool bForceSendConnnectionData)
{
	MLT_OutgoingPacketSynthesizer packetSynth;

	if(_pTunnel->GetDestinationTunnelId() == 0xffffffffu || _pTunnel->GetStatus() != MLT_Tunnel::Status::Connected || bForceSendConnnectionData || !_bOnceConnected)
		packetSynth.SetHeaderWithConnectionData(_pTunnel->GetDestinationTunnelId(), _DestinationLinkId, (uint8_t *)_pTunnel->_ConnectionData.Begin(), uint16_t(_pTunnel->_ConnectionData.GetLength()), _pTunnel->GetAppId(), _pTunnel->_GetSessionId(), _pTunnel->_GetDestinationSessionId(), _pTunnel->GetTunnelId(), _LinkId);
	else
		packetSynth.SetHeader(_pTunnel->GetDestinationTunnelId(), _DestinationLinkId, _pTunnel->_GetSessionId(), _pTunnel->_GetDestinationSessionId(), _pTunnel->GetTunnelId(), _LinkId);

	// check if we want needs to request a heartbeat
	bool requestHeartbeat = _NeedsToRequestHeartbeat();
	if(requestHeartbeat)
	{
		packetSynth.SetRequestHeartbeatReplyFlag();
		bWithSN = true;			// heartbeat requests always include SN in the packet so that the destination could include it in the reply.
	}

	packetSynth.SetQosData(bWithSN ? _SendSerialNum : 0xffffffff, _RecvSerialNumLargest, _RecvSerialNumBits);

	if(pTunnelData && tunnelDataLen)
		packetSynth.SetTunnelData(pTunnelData, tunnelDataLen);

	PacketBuf<> packetBuf;
	if(!packetSynth.SynthesizePacket(packetBuf, _pTunnel->GetCipherSecret(), _pTunnel->GetTunnelUID()))
		return false;

#if defined(PLATFORM_DEBUG_BUILD)
	{
		MLT_IncomingPacketParser parser((uint8_t *)packetBuf.GetData(), packetBuf.GetLength());
		if(!parser.IsHeaderValid())
		{
			_LOG_ERROR("Sending invalid packet");
		}

		if(!parser.ParseBody(_pTunnel->GetCipherSecret()))
		{
			_LOG_ERROR("Sending invalid packet");
		}
	}
#endif

	bool ret;
	if(_bDirectLink)
		ret = _pTunnel->_pCore->Send(packetBuf, _DestinationAddress);
	else
		ret = _pTunnel->_pCore->Send(packetBuf, _DestinationAddress, _BouncerAddress);

	uint64_t curTime = uint64_t(os::Timestamp::Get());
	_LastSent = curTime;
	_SentTotal++;

	if(_FirstOutgoingPacketTs == 0)
		_FirstOutgoingPacketTs = curTime;

	if(ret && requestHeartbeat)
	{
		_lastHeartbeatRequestTS = curTime;
		_lastHeartbeatRequestSN = _SendSerialNum;
		_unackedHeartbeatRequests.emplace(_SendSerialNum, curTime);
	}

	if(bWithSN)
	{
		if(_SendSerialNum > 64)
		{
			// TODO: report dropped 0 bits, i.e. the sent packets that were never reported as received.
		}

		_SendSerialNum++;
		_AckedSerialNumBits <<= 1;
	}

	return ret;
}

void MLT_Link::OnRecv(const MLT_IncomingPacketParser &parser)
{
	uint64_t curTime = uint64_t(os::Timestamp::Get());
	_LastRecv = curTime;
	//if(_bDirectLink)
	//{
	//	_LOG("Link " << _LinkId << ", Recv " << _LastRecv);
	//}
	_RecvTotal++;

	//if(parser.RequestsHeartbeatReply())
	//{
	//	_LOG("[MLT] Received heartbeat request on tunnel " << _pTunnel->GetTunnelId() << ", link " << _LinkId);
	//}

	if(parser.GetBodyHeader()->senderLinkId == 0xffffffffu)
		return;

	if(_DestinationLinkId == 0xffffffffu || _DestinationLinkId < parser.GetBodyHeader()->senderLinkId)
	{
		_DestinationLinkId = parser.GetBodyHeader()->senderLinkId;

		_RecvSerialNumLargest = 0;
		_RecvSerialNumBits = 0;
		_RecvSerialNumBitsToBeReported = 0;
	}

	_UpdateQoS(parser.GetQosData());

	// unlike tunnel id, link id is always encrypted in the packet, therefore we always want the destination to know our link id to make parsing faster.
	// when the destination requests a heartbeat, we also need to reply immediately
	if(!_bDestinationKnowsOurLinkId || parser.RequestsHeartbeatReply())
	{
		bool res = SendPacket(nullptr, 0, !_bDestinationKnowsOurLinkId, false);			// heartbeat replies don't necessarily need to include SN, so the parameter only depends on _bDestinationKnownOurLinkId
		//if(_bDirectLink)
		//{
		//	_LOG("Link " << _LinkId << " heartbeat reply sent " << (res ? "true" : "false"));
		//}
	}

	if(_bDestinationKnowsOurLinkId && _DestinationLinkId != 0xffffffff && _Latency != 0xffff)
	{
		if(!_bConnected)
		{
			_bConnected = true;
			_bOnceConnected = true;
			_pTunnel->_OnLinkConnect(_LinkId);
		}
	}
}

bool MLT_Link::_NeedsToRequestHeartbeat()
{
	uint64_t curTime = uint64_t(os::Timestamp::Get());

	// There are 3 cases here:
	// 1. Link just created and hasn't been connected yet. (bConnected = false, bOnceConnected = false)
	// 2. Link is connected. (bConnected = true, bOnceConnected = true)
	// 3. Link is disconnected after being connected. (bConnected = false, bOnceConnected = true)
	// Only in case 3, we want to send the heartbeat packets in lower frequency.
	if(!_bConnected && _bOnceConnected)
		return curTime >= _lastHeartbeatReplyTS + _HeartbeatDuration && curTime > _lastHeartbeatRequestTS + _HeartbeatRequestIntervalDisconnected;
	else
		return curTime >= _lastHeartbeatReplyTS + _HeartbeatDuration && curTime > _lastHeartbeatRequestTS + _HeartbeatRequestInterval;
}

uint64_t MLT_Link::GetNoIncomingTrafficTime() const
{
	uint64_t lastIncomingActivity = std::max(_LastRecv, _FirstOutgoingPacketTs);

	uint64_t curTime = uint64_t(os::Timestamp::Get());
	if(lastIncomingActivity > curTime)
		return 0;

	return curTime - lastIncomingActivity;
}

void MLT_Link::OnTick(uint32_t tick_in_100ms, int64_t net_ts_in_ms)
{
	if(_NeedsToRequestHeartbeat())						// there's a heartbeat to send
		SendPacket(nullptr, 0, true, false);
	else if(_RecvSerialNumBitsToBeReported != 0)		// there's an ack to send
	{
		SendPacket(nullptr, 0, false, false);
		_RecvSerialNumBitsToBeReported = 0;
	}

	// only keep track of the last 10 heartbeats
	while(_unackedHeartbeatRequests.size() > 10)
		_unackedHeartbeatRequests.erase(_unackedHeartbeatRequests.begin());

	uint64_t noIncomingTrafficTime = GetNoIncomingTrafficTime();
	if(noIncomingTrafficTime > _ConnectionTimeout)
	{
		//if(_bDirectLink)
		//{
		//	_LOG("[MLT] " << _pTunnel->GetTunnelId() << "." << _LinkId << ": Disconnected: last = " << _LastRecv << ", cur = " << uint64_t(os::Timestamp::Get()));
		//}

		_bConnected = false;
		_pTunnel->_OnLinkDisconnect(_LinkId);
	}
}

void MLT_Link::_UpdateQoS(const MLT_Packet::PKT_LINK_QOS_DATA *data)
{
	if(data)
	{
		// update receive table
		if(data->LPSN != 0xffffffff)		// if the packet doesn't have an SN, just ignore that part
		{
			if(data->LPSN <= _RecvSerialNumLargest && _RecvSerialNumLargest - data->LPSN < 64)
			{
				if((_RecvSerialNumBits & (1ull << (_RecvSerialNumLargest - data->LPSN))) == 0)
				{
					_RecvSerialNumBits |= 1ull << (_RecvSerialNumLargest - data->LPSN);
					_RecvSerialNumBitsToBeReported |= 1ull << (_RecvSerialNumLargest - data->LPSN);
					_RecvSerialNumBitsTime[data->LPSN % 64] = _LastRecv;
				}
			}
			else if(data->LPSN > _RecvSerialNumLargest)
			{
				uint32_t numDroppedHistory = data->LPSN - _RecvSerialNumLargest;
				if((_RecvSerialNumBitsToBeReported >> (64 - numDroppedHistory)) != 0)		// older SN are at higher bits, check if there's any 1 bit there
				{
					SendPacket(nullptr, 0, false, false);
					_RecvSerialNumBitsToBeReported = 0;
				}

				_RecvSerialNumLargest = data->LPSN;
				// shift-out the old entries and set the bit for the current packet
				_RecvSerialNumBits <<= numDroppedHistory;
				_RecvSerialNumBitsToBeReported <<= numDroppedHistory;
				_RecvSerialNumBits |= 1;
				_RecvSerialNumBitsToBeReported |= 1;
				_RecvSerialNumBitsTime[data->LPSN % 64] = _LastRecv;		// also update the time
			}
			else
			{
				// receiving an old packet, unexpected
				//_LOG("[MLT] " << _pTunnel->GetTunnelId() << "." << _LinkId << ": old packet incoming " << data->LPSN << " << " << _RecvSerialNumLargest);
			}

		}

		// update send table
		if(data->ackLPSNBase < _SendSerialNum)		// The last sent packet has SN of _SendSerialNum - 1, the destination cannot report anything larger than that.
		{
			if(data->ackLPSNBase <= 0xffffffff - 64 && data->ackLPSNBase + 64 > _SendSerialNum - 1)
			{
				_AckedSerialNumBits |= data->ackLPSNMask << (_SendSerialNum - 1 - data->ackLPSNBase);
			}
		}

		// update heartbeat data
		//if((data->ackLPSNMask & 1) != 0)
		{
			for(auto& itor : _unackedHeartbeatRequests)
			{
				uint32_t heartbeatSN = itor.first;
				if(data->ackLPSNBase >= heartbeatSN && data->ackLPSNBase - heartbeatSN < 64 && ((data->ackLPSNMask & (1ull << (data->ackLPSNBase - heartbeatSN))) != 0))
				{
					uint64_t curTime = uint64_t(os::Timestamp::Get());
					_lastHeartbeatReplyTS = curTime;
					_lastHeartbeatReplySN = heartbeatSN;

					uint64_t heartbeatLatency = std::min(curTime - itor.second, (uint64_t)0xffffull);
					if(data->ackLPSNBase >= _LatencyHeartbeatSN)		// it might happen that the reply of older heartbeat packets arrive later than newer ones, in which case they should be ignored
					{
						_Latency = uint16_t(heartbeatLatency);
						_LatencyHeartbeatSN = data->ackLPSNBase;
					}

					//_LOG("[MLT] Received heartbeat reply on tunnel " << _pTunnel->GetTunnelId() << ", link " << _LinkId);
				}
			}

			while(_unackedHeartbeatRequests.size() && _unackedHeartbeatRequests.begin()->first <= _LatencyHeartbeatSN)
				_unackedHeartbeatRequests.erase(_unackedHeartbeatRequests.begin());
		}
	}
}

static rt::String BitmaskToString(uint64_t mask, uint8_t numBits)
{
	rt::String ret;
	for(uint8_t i = 0; i < numBits; i++)
		ret += (mask & (1ull << i)) ? '*' : '?';

	return ret;
}

rt::String MLT_Link::GetStatusString()
{
	rt::String ret;
	ret = rt::tos::Number(_LinkId) + rt::SS(" <-> ") + (_DestinationLinkId == 0xffffffff ? rt::tos::Number(-1) : rt::tos::Number(_DestinationLinkId)) + (_bConnected ? rt::SS(" (Connected): ") : rt::SS(" (Disconnected): "));
	if(_bDirectLink)
		ret += rt::SS("[") + tos(_DestinationAddress) + rt::SS("]");
	else
		ret += rt::SS("[") + tos(_BouncerAddress) + rt::SS(" -> ") + tos(_DestinationAddress) + rt::SS("]");

	uint64_t curTime = uint64_t(os::Timestamp::Get());
	ret += rt::SS(", PSN: ") + rt::tos::Number(_SendSerialNum > 0 ? _SendSerialNum - 1 : 0) + rt::SS(" <-> ") + rt::tos::Number(_RecvSerialNumLargest);
	ret += rt::SS(", P: ") + BitmaskToString(_AckedSerialNumBits, 10) + rt::SS(" <-> ") + BitmaskToString(_RecvSerialNumBits, 10);
	ret += rt::SS(", PTS: -") + rt::tos::Number(curTime - _LastSent) + rt::SS(" <-> -") + (_LastRecv == 0 ? rt::String_Ref("?") : rt::tos::Number(curTime - _LastRecv));
	ret += rt::SS(", HB: -") + rt::tos::Number(curTime - _lastHeartbeatRequestTS) + rt::SS("(SN: ") + rt::tos::Number(_lastHeartbeatRequestSN)+ rt::SS(") <-> -")
		+ (_lastHeartbeatReplyTS == 0 ? rt::String_Ref("?") : rt::tos::Number(curTime - _lastHeartbeatReplyTS)) + rt::SS("(SN: ") + rt::tos::Number(_lastHeartbeatReplySN) + rt::SS(")");
	ret += rt::SS(", L: ") + rt::tos::Number(_Latency) + rt::SS("(SN: ") + rt::tos::Number(_LatencyHeartbeatSN) + rt::SS(")");

	return ret;
}

} // namespace upw
