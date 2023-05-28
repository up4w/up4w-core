#pragma once
#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_packet.h"
#include "mlt_packet_incoming.h"

namespace upw
{

class MLT_Tunnel;

class MLT_Link
{
private:
	bool							_bConnected = false;
	bool							_bOnceConnected = false;

	// all are local times
	uint64_t						_LastRecv = 0;						// msec
	uint64_t						_LastSent = 0;						// msec
	uint16_t						_Latency = 0xffff;					// msec
	uint32_t						_LatencyHeartbeatSN = 0;			// The SN of the heartbeat packet used to calculate latency
	uint32_t						_SendSerialNum = 0;					// id of the next packet to be sent, CAREFUL: this is the SN to be used for the next packet, not the SN of the last sent packet.
	uint64_t						_AckedSerialNumBits = 0;			// whether packets with id _SendSerialNum - 1, _SendSerialNum - 2, ... were successfully delivered.
	uint32_t						_RecvSerialNumLargest = 0;			// largest id of all received packets (note: this might not be the last received packet since UDP traffic is out of order)
	uint64_t						_RecvSerialNumBits = 0;				// whether packets with id _RecvSerialNumBits - 0, _RecvSerialNumBits - 1, ... were received.
	uint64_t						_RecvSerialNumBitsToBeReported = 0;	// which receive bits have not yet been report to the destination 
	uint64_t						_RecvSerialNumBitsTime[64];			// the time when each of the packets were received
	uint32_t						_SentTotal = 0;						// total number of packets sent
	uint32_t						_RecvTotal = 0;						// total number of packets received
	uint32_t						_LostTotal = 0;

	static constexpr uint16_t		_QoSMaxDelayInAck = 5000;			// msec, maximum allowed delay before ACK of an outgoing packet is received before considering the packet as lost
	static constexpr uint16_t		_QosMaxDelayInDelivery = 2000;		// msec, maximum allowed time before an incoming packet is considered lost. i.e. after another packet with larger SN is received.
	
	static constexpr uint16_t		_HeartbeatDuration = 5000;			// msec, if there's no heartbeat reply in the last _HeartbeatDuration msec, request a new one
	static constexpr uint16_t		_HeartbeatRequestInterval = 1000;	// msec, request heartbeat reply at this interval until one is received
	static constexpr uint16_t		_HeartbeatRequestIntervalDisconnected = 5000;	// msec, request heartbeat reply at this interval until one is received, when the link is disconnected
	uint64_t						_lastHeartbeatRequestTS = 0;		// timestamp when the last heartbeat request was sent
	uint32_t						_lastHeartbeatRequestSN = 0;		// SN of the last sent heartbeat request
	uint64_t						_lastHeartbeatReplyTS = 0;			// timestamp when the last heartbeat reply was received
	uint32_t						_lastHeartbeatReplySN = 0;			// SN of the last replied heartbeat
	std::map<uint32_t, uint64_t>	_unackedHeartbeatRequests;			// the heartbeat requests that hasn't got a reply yet, mapped to the timestamp when they were sent.

	static constexpr uint16_t		_ConnectionTimeout = 10000;			// msec, when no packet from destination received in this period of time, the link is considered disconnected
	uint64_t						_FirstOutgoingPacketTs = 0;			// timestamp the first outgoing packet got sent.

	const NetworkAddress	_DestinationAddress;
	const NetworkAddress	_BouncerAddress;
	const bool				_bDirectLink;

	MLT_Tunnel* const		_pTunnel;
	const uint32_t			_LinkId;
	uint32_t				_DestinationLinkId = 0xffffffff;
	bool					_bDestinationKnowsOurLinkId = false;

private:
	void _UpdateQoS(const MLT_Packet::PKT_LINK_QOS_DATA *data);
	bool _NeedsToRequestHeartbeat();
public:
	MLT_Link(const NetworkAddress &destinationAddr, const NetworkAddress *bouncerAddr, MLT_Tunnel *pTunnel, uint32_t linkId);

	void OnRecv(const MLT_IncomingPacketParser &parser);
	void OnTick(uint32_t tick_in_100ms, int64_t net_ts_in_ms);

	bool SendPacket(uint8_t *pTunnelData, uint16_t tunnelDataLen, bool bWithSN, bool bForceSendConnnectionData);

	void SetDestinationKnowsOurLinkId(bool b) { _bDestinationKnowsOurLinkId = b; }

	uint64_t GetNoIncomingTrafficTime() const;
	uint16_t GetLatency() const { return _Latency; }
	uint32_t GetLinkId() const { return _LinkId; }
	uint32_t GetDestionationLinkId() const { return _DestinationLinkId; }
	const NetworkAddress& GetLinkAddress() const { return _bDirectLink ? _DestinationAddress : _BouncerAddress; }
	bool IsDirectLink() const { return _bDirectLink; }
	const NetworkAddress& GetDestinationAddress() const { return _DestinationAddress; }
	const NetworkAddress* GetBouncerAddress() const { return _bDirectLink ? nullptr : &_BouncerAddress; }
	bool OnceConnected() const { return _bOnceConnected; }

	rt::String GetStatusString();

};

} // namespace upw