#pragma once
#include "dht_tx_swarm.h"


namespace upw
{

class DhtTxJoinSwarm: public DhtTxSwarm
{

protected:
	rt::FrequencyDivision	_PingPeersBackwardTimer		={DHT_SWARM_PING_INTERVAL/5, DHT_SWARM_PING_INTERVAL/10};
	ULONGLONG				_AnnounceToken;

public:
	static const UINT TX_TYPE = RQTAG_TXTYPE_JOINSWARM;

protected:

	bool					_SwarmPeersBootstrapListDirty = false;
	rt::BufferEx<Node>		_SwarmPeersForward;		// outgoing
	rt::BufferEx<Node>		_SwarmPeersBackward;	// incoming
	bool					_SwarmPeersForwardDirty = false;
	bool					_SwarmPeersBackwardDirty = false;
	float					_AverageLatencyForward = 2;
	float					_AverageLatencyBackward = 2;
    void                    _PingAllPeers(bool force = false);
    
	void					_UpdateOutputPeers(bool enforce);
	void					_UpdateBootstrapList();
	bool					_IsNodesFull() const { return _SwarmPeersBackward.GetSize() >= _ExpectedNum*2 && _SwarmPeersForward.GetSize() >= _ExpectedNum*2; }

	LONGLONG				_bActiveAnnouncementStartTime;
	bool					_IsActiveAnnouncing() const { return _bActiveAnnouncementStartTime > 0; }
	LONGLONG				_bActiveAnnouncementEndTime;
	void					_StopAllActiveWorks();

	SwarmPeerContact		_OnSwarmPeerContacted(const DhtMessageParse& msg, const PacketRecvContext& ctx, UINT tick, float latency, bool auto_add, bool query); // true for in-swarm peers
	void					_ActiveAnnouncePeer();
	void					_SendContactMessageToPeers(const NetworkAddress* peers, uint32_t count, bool in_peerlist);

public:
	DhtTxJoinSwarm(const DhtAddress& target, MainlineDHT& dht, UINT expected_num, const DhtAddress* nodeid = nullptr, DWORD app = 0, const DhtAddress* private_secret = nullptr, const rt::String_Ref& boot_file = nullptr);

    void		Awaken();
	bool		IsMature() const;
	void		Iterate();
	void		Leave();
	void		OnReply(const DhtTxReplyContext& rc);
	void		CopyPeersAsBouncers(rt::BufferEx<NetworkAddress>& bouncers, rt::BufferEx<NetworkAddress>& bouncers_altip, rt::BufferEx<NetworkAddress>& destination);

	//void		OnAnnouncePeer(const DhtMessageParse& msg, const PacketRecvContext& ctx);
	void		InitiatePeerAnnoucement();
	void		Jsonify(rt::Json& json) const;
	void		GetStateReport(rt::String& out, UINT tick);

	// Following calls need no Lock
	auto&		GetPeers() const { return *_OutputPeers_Front; }
	void		OnPing(const DhtMessageParse& msg, const PacketRecvContext& ctx);
	void		OnGetPeers(const DhtMessageParse& msg, const PacketRecvContext& ctx);
};

} // upw