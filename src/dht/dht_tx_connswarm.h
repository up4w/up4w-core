#pragma once
#include "dht_tx_swarm.h"


namespace upw
{

class DhtTxConnSwarm: public DhtTxSwarm
{

public:
	static const UINT TX_TYPE = RQTAG_TXTYPE_CONNSWARM;

protected:
	bool					_SwarmPeersBootstrapListDirty = false;
	rt::BufferEx<Node>		_SwarmPeers;		// outgoing
	bool					_SwarmPeersDirty = false;
	float					_AverageLatencyForward = 2;
    void                    _PingAllPeers(bool force = false);
    
	void					_UpdateOutputPeers(bool enforce);
	void					_UpdateBootstrapList();

	bool					_IsNodesFull() const { return _SwarmPeers.GetSize() >= _ExpectedNum*2; }
	void					_StopAllActiveWorks();

	SwarmPeerContact		_OnSwarmPeerContacted(const DhtMessageParse& msg, const PacketRecvContext& ctx, UINT tick, float latency, bool auto_add, bool query); // true for in-swarm peers
	void					_SendContactMessageToPeers(const NetworkAddress* peers, uint32_t count);

public:
	DhtTxConnSwarm(const DhtAddress& target,
	                 MainlineDHT& dht,
					 UINT expected_num, 
					 const DhtAddress* nodeid = nullptr, 
					 DWORD app = 0,
                     const DhtAddress* private_secret = nullptr,
					 const rt::String_Ref& boot_file = nullptr);

    void		Awaken();
	bool		IsMature() const;
	void		Iterate();
	void		OnReply(const DhtTxReplyContext& rc);
	void		Jsonify(rt::Json& json) const;
	void		GetStateReport(rt::String& out, UINT tick);

	// Following calls need no Lock
	auto&		GetPeers() const { return *_OutputPeers_Front; }
};

} // namespace upw