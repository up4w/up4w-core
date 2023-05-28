#pragma once

#include "../externs/miniposix/core/inet/inet.h"
#include "net_types.h"
#include "netsvc_types.h"
#include "./dht/dht_message.h"
#include "./dht/dht_tx_joinswarm.h"
#include "./dht/dht_tx_connswarm.h"


namespace upw
{

class NetworkServiceCore;

class LocalSwarm
{
	int		__LocalSwarmPeerScanBase;

protected:
#pragma pack(push,1)
	enum PacketMsgId
	{
		PMID_GET = 1,
		PMID_GET_REPLY,
		PMID_PING,
		PMID_PING_REPLY,
		PMID_FINDNODE,
		PMID_FINDNODE_REPLY,
		PMID_GETPEER,
		PMID_GETPEER_REPLY,
	};
	enum PacketFlag
	{	
		PCKF_REPLY_ADDITIONAL_GET = 0x0001, // for PMID_PING packets that expecting an additional get reply (PMID_GET_REPLY) besides normal ping reply
	};
	struct PacketHeader
	{
		static const WORD	VERSION = 0x016c;
		WORD				Version;
		BYTE				Msg;  // PacketMsgId
		BYTE				Flag;
		ULONGLONG			AppName;
	};
	typedef IPv4 Host;
	struct PacketGet: public PacketHeader
	{
		static const UINT	MAX_COUNT = 167;

		ULONGLONG			CheckSum;
		WORD				HostCount;
		Host				Hosts[MAX_COUNT];

		UINT				GetSize() const { return sizeof(PacketHeader) + 8 + 2 + HostCount*sizeof(Host); }
		ULONGLONG			GetCheckSum() const;
		bool				IsValid() const { return CheckSum == GetCheckSum(); }
	};
	struct PacketPing: public PacketHeader
	{	
		LONGLONG			Timestamp;
		Host				ObservedByRecipient;
		DhtAddress			SenderDHT;
		NetworkNodeDesc		SenderDesc;
	};
	struct PacketDHTQuery: public PacketHeader // PMID_FINDNODE, PMID_GETPEER
	{
		DhtAddress			Target;
		DWORD				SecureKey;
	};	
	struct PacketDhtIPList: public PacketHeader // PMID_FINDNODE_REPLY, PMID_GETPEER_REPLY
	{
		DWORD				SecureKey;
		BYTE				Count;
		NetworkAddress		Nodes[ (NET_DATAGRAMNETWORK_MTU - NET_PACKET_PREFIX_DEFAULT_SIZE - sizeof(PacketHeader) - 1)/sizeof(NetworkAddress) ];
		UINT				GetSize() const { return offsetof(PacketDhtIPList, Nodes) + Count*sizeof(NetworkAddress); }
	};
	struct Node: public DhtNodeBase
	{
		NetworkNodeDesc		NodeDesc;
		bool				IsExternal;
		bool				operator == (const NetworkAddress& h) const { return h == NetAddress; }
		bool				IsGone(UINT tick) const 
							{	float pl = rt::min(latency_average, 10.0f);
								return tick - last_recv > pl*DHT_LOCALSWARM_NODE_GONE_LATENCY_MULTIPLIER + 3100/NET_TICK_UNIT_FLOAT; 
							}
		bool				IsNearlyGone(UINT tick) const 
							{	float pl = rt::min(latency_average, 10.0f);
								return tick - last_recv > pl*DHT_LOCALSWARM_NODE_GONE_LATENCY_MULTIPLIER;
							}
	};

#pragma pack(pop)

protected:
	rt::TopWeightedValues<WORD,  3>		_ExternalPorts;
	rt::TopWeightedValues<DWORD, 2>		_ExternalIPs;

	bool					_HasActiveExternalPeer;
	UINT					_ActiveSubnetSwarmPeersCount;

	LocalPeerList*			_pOutputPeers_Front;
	LocalPeerList*			_pOutputPeers_Back;
	rt::BufferEx<Node>		_SwarmPeers;
	bool					_bSwarmPeersDirty;
	os::CriticalSection		_SwarmPeersCS;
	static ULONGLONG		_AppName;

	void _OnGetReply(const PacketGet& packet);
	void _OnGet(const PacketGet& packet, const PacketRecvContext& ctx);
	void _OnPingReply(const PacketPing& packet, const PacketRecvContext& ctx);
	void _OnPing(const PacketPing& packet, const PacketRecvContext& ctx);

	void _OnDhtFindNodeReply(const PacketDhtIPList& packet, const PacketRecvContext& ctx);
	void _OnDhtFindNode(const PacketDHTQuery& packet, const PacketRecvContext& ctx);
	void _OnDhtGetPeerReply(const PacketDhtIPList& packet, const PacketRecvContext& ctx);
	void _OnDhtGetPeer(const PacketDHTQuery& packet, const PacketRecvContext& ctx);

	void _SendPing(const NetworkAddress& h, bool is_external) const;
	void _PreparePacketGet(PacketGet& p, UINT msg_type, DWORD local_ip = 0);
	void _LogMsg(const PacketHeader& packet, const NetworkAddress& from);
	void _BroadcastPacketGet(bool as_reply = false);
	void _OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx);

protected:
	DWORD					_DhtQuerySecKey;
	DWORD					_DhtQuerySecKeyPrev;
	bool					_CheckDhtQuerySecKey(DWORD x) const { return x == _DhtQuerySecKey || x == _DhtQuerySecKeyPrev; }
	void					_HelpDhtBootstrap(const NetworkAddress* to = nullptr) const;

	inet::Socket			_LocalDiscoverySocket;
	UINT					_LocalDiscoveryPort;
	os::Thread				_LocalDiscoveryThread;
	void					_LocalDiscoveryFunc();

	DWORD					_BroadcastAddresses[NET_LOCAL_ADDRESS_MAXCOUNT];
	UINT					_BroadcastAddressCount;

	const NetworkNodeDesc*	_pNodeDesc;
	NetworkServiceCore*		_pNet;
	UINT					_Tick;

	rt::FrequencyDivision	_fd_DHT_LOCALSWARM_EXTERNAL_DISCOVERY = DHT_LOCALSWARM_EXTERNAL_DISCOVERY_INTERVAL;
	rt::FrequencyDivision	_fd_DHT_LOCALSWARM_BROADCAST_DISCOVERY = DHT_LOCALSWARM_BROADCAST_DISCOVERY_INTERVAL;

public:
	LocalSwarm(NetworkServiceCore* p, const NetworkNodeDesc& nd, UINT expected_num);
	~LocalSwarm();
	void			CloseDiscoverySocket(){ _LocalDiscoverySocket.Close(); }
	void			Awaken();

	bool			IsExternalAddressAvailable() const;
	IPv4			GetExternalAddress() const;
	UINT			GetExternalPort() const;
	UINT			GetPeerCount() const { return _pOutputPeers_Front->Count; }
	auto&			GetPeers() const { return *_pOutputPeers_Front; }
	void			InvitePeer(const NetworkAddress& ip) const;

	// Driven by Network
	void			ResetExternalPort();
	void			ForceRefresh();
	void			SetBroadcastAddresses(const DWORD* cast_addr, UINT co);
	void			OnTick(UINT tick);
	UINT			GetSwarmSize() const { return (UINT)_SwarmPeers.GetSize(); }
	void			GetStateReport(rt::String& out);
	void			GetState(NetworkState_LSM& ns);

	static void		SetMessageAppName(const rt::String_Ref& appname);
};

} // namepsace upw