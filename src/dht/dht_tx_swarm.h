#pragma once

#include "dht_base.h"
#include "dht_message.h"
#include "dht_queue.h"
#include "dht_tx_nodes.h"
#include "dht_txns.h"

namespace upw
{

class DhtTxSwarm: public os::CriticalSection 
				  , protected DhtTxRecentHosts
{
	template<typename T>
	friend class _details::DhtTxns;

protected:
	UINT					_TX;
	UINT					_TX_TYPE;
	DhtAddress				_NodeId;
	DhtAddress				_Target;
	ULONGLONG				_SecureL1Mask;
	ULONGLONG				_SecureL1Orig;
	DWORD					_AppTag;
	UINT					_ExpectedNum;
	rt::String				_StockBootstrapFilename;
	int32_t					_BootstrapBoostCountDown = DHT_SWARM_BOOTSTRAP_BOOST_COUNT;

	DhtSwarmEventCallback	_EventCallback = nullptr;
	LPVOID					_EventCallbackCookie = nullptr;

	rt::FrequencyDivision	_PingPeersForwardTimer		= DHT_SWARM_PING_INTERVAL/5;
	rt::FrequencyDivision	_RefreshOutputPeersTimer	= DHT_SWARM_PING_INTERVAL;
	rt::FrequencyDivision	_SwarmBootstrapTimer		= DHT_SWARM_BOOTSTRAP_INTERVAL;
	rt::FrequencyDivision	_SwarmBootstrapBoostTimer	= DHT_SWARM_BOOTSTRAP_BOOST_INTERVAL;
	rt::FrequencyDivision	_UpdateBootstrapFileTimer	={DHT_SWARM_BOOTSTRAP_SAVE_INTERVAL, DHT_SWARM_BOOTSTRAP_SAVE_INTERVAL/2};

	BYTE					_SecureL1Distance(const DhtAddress& x) const
							{	ULONGLONG* d = (ULONGLONG*)&x.addr[4];
								return (BYTE)rt::NonzeroBits(((((d[0]^_SecureL1Mask) + d[1]) ^ (ULONGLONG&)x) + _SecureL1Mask) ^ _SecureL1Orig);
							}
public:
	const DhtAddress&		GetTarget() const { return _Target; }
	UINT					GetTX() const { return _TX; }

	enum SwarmPeerContact
	{	
		SPC_REJECT = 0,
		SPC_UPDATED,
		SPC_ADDED,
		SPC_LEAVE,
	};

	enum NodeFlag : uint16_t
	{
		NODE_FLAG_ZERO			= 0,
		NODE_FORWARD			= 0x001,  // must be one
		NODE_IPRESTRICTVERIFIED	= 0x002,
		NODE_DISCARD			= 0x004,
		NODE_CLOAKED_MYIP		= 0x008
	};

	struct Node: public DhtNodeBase
	{	
		TYPETRAITS_DECLARE_POD;
		NetworkPeerDesc		PeerDesc;
		UINT				LastQueryRecv;	// backward node use that
		NetworkAddress		ExternalIP;		// reported by peers
		union
		{
			CloakedIPv4		EncryptIPv4;	// if ExternalIP.IsIPv4() && NODE_CLOAKED_MYIP
			CloakedIPv6		EncryptIPv6;	// if ExternalIP.IsIPv6() && NODE_CLOAKED_MYIP
		};
		NetworkAddress		AlternativeIP;	// reported by peers
		NodeFlag			Flag;
		BYTE				SecureL1Distance;

		UINT				Age(UINT tick) const { return rt::max(0, (int)tick - discover_time); }  // in tick
		UINT				Lifetime() const { return rt::min((UINT)latency_average, 50U) + DHT_SWARM_PING_INTERVAL * (5 - 2*(Flag&NODE_FORWARD));	}
		int					BackwardTTL(UINT tick) const { return ((int)Lifetime()) - (tick - LastQueryRecv); }
		bool				IsBackwardEstablished(UINT tick) const { ASSERT(!IsForward()); return LastQueryRecv && ((int)tick - (int)LastQueryRecv) < (int)Lifetime(); }

		int					TTL(UINT tick) const { return ((int)Lifetime()) - (tick - last_recv); }
		bool				IsAlive(UINT tick) const { return TTL(tick) >= 0; }

		bool				IpRestrictVerified() const { return Flag&NODE_IPRESTRICTVERIFIED; }
		bool				IsForward() const { return Flag&NODE_FORWARD; }
							bool operator < (const Node& n) const
							{	//return latency_average < n.latency_average;
								if(IpRestrictVerified() == n.IpRestrictVerified())return latency_average < n.latency_average;
								return IpRestrictVerified();
							}
	};

protected:
	UINT					_EstablishedBackward = 0;
	UINT					_DiscoveredForward = 0;
	PeerList*				_OutputPeers_Front = nullptr;
	PeerList*				_OutputPeers_Back = nullptr;

protected:
	DhtAddress				_PrivateSwarmSecret;		// "ps" -> 8:xxxxxxxx
	bool					_IsPrivateSwarm = false;
	ULONGLONG				_GetPrivateSwarmPacketNum(const NetworkAddress& from) const { return from.IsIPv4()?_GetPrivateSwarmPacketNum(from.IPv4()):_GetPrivateSwarmPacketNum(from.IPv6()); }
	ULONGLONG				_GetPrivateSwarmPacketNum(const IPv4& from) const;
	ULONGLONG				_GetPrivateSwarmPacketNum(const IPv6& from) const;
	void					_AppendPrivateSwarmPacketNum(PacketBuf<>& buf, NETADDR_TYPE type) const;
	bool					_IsRejectedByPrivateSwarm(const DhtMessageParse& msg, const PacketRecvContext& ctx){ return _IsPrivateSwarm && ((msg.fields_parsed&MSGFIELD_PRIVATESWARM_PNUM) == 0 || msg.private_swarm_packet_num != _GetPrivateSwarmPacketNum(ctx.RecvFrom)); }
	void					_RejectPeer(const NetworkAddress& addr){ AddQueried(addr); }

	LONGLONG				_HostsClearTime = 0;
	LONGLONG				_ActiveDiscoveringStartTime = 0;
	bool					_ActiveDiscoveredByStockBootstrapList = false;
	bool					_IsActiveDiscovering() const { return _ActiveDiscoveringStartTime > 0; }
	void					_StartActiveDiscovery(bool is_mature);

protected:
	void					_PrintPeers(bool forward, const rt::BufferEx<Node>& peers, rt::String& out) const;
	void					_UpdateNodeAuxInfo(Node& n, const DhtMessageParse& msg, const NetworkAddress& from);
	void					_RemoveDuplicatedInsecurePeers(rt::BufferEx<Node>& swarm_peers, UINT open, UINT q, NETADDR_TYPE net_type, bool is_forward, const DhtAddress& dht_addr);
	void					_AppendAltIp(const NetworkAddress& peer, PacketBuf<>& buf) const;
	void					_AppendCloakedIp(const NetworkAddress& to, PacketBuf<>& buf) const;
	void					_SendContactMessage(const NetworkAddress& to, bool no_discover, bool in_list, PACKET_SENDING_FLAG flag) const;
	bool					_SendContactMessageFromBootstrapFile() const;
    float					_PingScan(bool no_discover, bool force, rt::BufferEx<Node>& peers) const;
	void					_InvokePeerEvent(DhtTxJoinSwarmEventIds evt, const DhtNodeBase& node) const { if(_EventCallback)_EventCallback(_EventCallbackCookie, _TX, node, evt); }

public:
	DhtTxSwarm(const DhtAddress& target,
	             MainlineDHT& dht,
				 UINT expected_num, 
				 const DhtAddress* nodeid = nullptr, 
				 DWORD app = 0,
                 const DhtAddress* private_secret = nullptr,
				 const rt::String_Ref& boot_file = nullptr);
	~DhtTxSwarm();

	void		Bootstrap();
	void		InvitePeer(const NetworkAddress& ip, bool in_list) const;

	UINT		GetDegree() const { return _ExpectedNum; }
	void		RejectPeer(const NetworkAddress& n){ ASSERT(IsLockedByCurrentThread()); _RejectPeer(n); }
	void		SetPeerEventCallback(DhtSwarmEventCallback cb, LPVOID cookie){ _EventCallback = cb; _EventCallbackCookie = cookie; }
	void		Jsonify(rt::Json& json) const;
};

} // namespace upw

STRINGIFY_ENUM_BEGIN(DhtTxSwarm::NodeFlag, upw)
STRINGIFY_ENUM_END(DhtTxSwarm::NodeFlag, upw)
