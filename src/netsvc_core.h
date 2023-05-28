#pragma once

#include "../externs/miniposix/core/os/kernel.h"
#include "../externs/miniposix/core/inet/datagram_pump.h"
#include "../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "netsvc_types.h"
#include "netsvc_events.h"

#if !defined(PLATFORM_IOS)
#define NET_USE_EVENTDRIVEN_SOCKET_IO
#endif

namespace upw
{

class MainlineDHT;	// discovery remote peers on Internet
class LocalSwarm;	// discovery peers in LAN
class SwarmBroadcast;
class GossipNetworkTime;
class LocalApi;
class GossipDataPropagation;
class MessageRelayCore;
class MultiLinkTunnels;

namespace itfc
{	struct StorageFactory;
} // namespace itfc

class NetworkServiceCore: public AsyncApiHandler
{
protected:

#if !defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	volatile INT			__ThreadId;
	inet::Socket			_Socket;
	inet::Socket			_SocketV6;
	rt::Buffer<os::Thread>	_RecvThreads;
	void					_RecvThreadFunc();
#endif

#if defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	struct UdpSocket: public inet::DatagramSocket
	{
		NetworkServiceCore&	_Core;
		UINT	Port;
		bool	V6;
		int32_t RcvbufSize = 0;

		bool Create(int port, bool ip_v6, int32_t rcvbufSize = 0);
		void OnRecv(inet::Datagram* g)
		{
			if(g)
			{
				if(!g->RecvSize)return;

				PacketRecvContext ctx;
				if(g->IsIPv6())
					ctx.RecvFrom.IPv6().Set(g->PeerAddressV6);
				else
					ctx.RecvFrom.IPv4().Set(g->PeerAddressV4);
		
				_Core.OnRecv(g->RecvBuf, g->RecvSize, ctx);
			}
			else if(!_Core.bWantStop)
			{
				_Core._UdpPump.RemoveObject(this);
				_LOG_POS_WARNING;
				while(!Create(Port, V6, RcvbufSize))os::Sleep(1000);
				_LOG_POS_WARNING;
				while(!_Core._UdpPump.AddObject(this))os::Sleep(500);
				_LOG_POS_WARNING;
			}
		}
		UdpSocket(NetworkServiceCore& c):_Core(c){}
	};
	UdpSocket						_Socket;
	UdpSocket						_SocketV6;
	inet::DatagramPump<UdpSocket>	_UdpPump;
#endif

	os::Thread				_TickingThread;
	void					_Ticking();
	UINT					_Tick;

	UINT					_LocalPort;
	UINT					_LocalPortV6;
	int32_t					_RcvbufSize = 0;

	struct LocalInterface
	{
		DWORD	LocalIP;
		DWORD	BroadcastIP;
		DWORD	LocalSubnetMask;
		char	InterfaceName[16];

		bool	IsSameSubnet(DWORD ip) const { return ((ip^LocalIP)&LocalSubnetMask) == 0; }
	};

	typedef os::ThreadSafeMutable<ext::fast_map<DWORD, LocalInterface>>	t_LocalNetInterfaces;

	inet::NetworkInterfaces	_InterfacesChanging;
	bool					_IsInterfacesReconfiging;

	t_LocalNetInterfaces	_LocalNetInterfaces;	// LocalIP
	IPv4					_NatExternalIP;
	DWORD					_NatInternalIP;

	IPv6					_NatExternalIPV6;
	BYTE					_NatInternalIPV6[16];

	void					_UpdateLocalAddress(bool force_populate = false);
	void					_UpdateLocalSwarmBroadcastAddresses();
	void					_CloseAllSockets();
	
    rt::String              _CachePath;
	GossipNetworkTime*		_pGNT;
	MainlineDHT*			_pDHT;
	LocalSwarm*				_pLSM;
	SwarmBroadcast*			_pSMB;
	GossipDataPropagation*	_pGDP;
	MultiLinkTunnels*		_pMLT;
	MessageRelayCore*		_pMRC;
	LocalApi*				_pAPI;

	UINT					_NatMappingState;
	UINT					_ConnectionState;

	struct NatTask: os::Thread
	{
		LocalInterface*		_pNic;
		NetworkServiceCore*	_pCore;
		bool				IsFinished() const { return _pCore == nullptr; }
	};

	os::CriticalSection		_DetermineConnectionThreadsCS;
	ext::fast_set<os::Thread*> _DetermineConnectionThreads;
	rt::String				_UPnpAppName;
	void					_DetermineConnectionState(os::Thread* th);
	void					_DetermineConnectionStateV6(os::Thread* th);
	void					_SetConnectionState(NETWORK_CONNECTION_STATE x);

	NetworkNodeDesc			_NodeDesc;
	DWORD					_NodeServiceActivated;
	bool					_DataServiceSuspended;
	BYTE					_CloakedIPSecret[16];

protected:
	struct _CallbackItem
	{	THISCALL_MFPTR	Func;
		LPVOID	Obj;
	};
	THISCALL_POLYMORPHISM_DECLARE_VOID(OnRecv, LPCVOID pData, UINT len, const PacketRecvContext& ctx);
	_CallbackItem			_OnRecvPacket[256];

	THISCALL_POLYMORPHISM_DECLARE_VOID(OnTick, UINT tick_in_100ms, LONGLONG net_ts_in_ms);
	_CallbackItem			_OnTick[16];
	UINT					_OnTickCBCount;

	bool					_OnExecuteCommand(const os::CommandLine& cmd, rt::String& out);
	bool					_Send(LPVOID p, UINT len, const NetworkAddress& to, PACKET_SENDING_FLAG flag);  // may downflow -6 bytes
	bool					_StartLocalServices(const rt::String_Ref& bind);

#if defined(PLATFORM_DEBUG_BUILD)
	struct _PrefixPacketStat
	{
		bool				IsSet = false;
		volatile int64_t	TotalSentBytes  = 0;
		volatile int64_t	TotalRecvBytes  = 0;
		volatile int64_t	TotalSentPacket = 0;
		volatile int64_t	TotalRecvPacket = 0;
	};
	_PrefixPacketStat	_PacketState[256];
	rt::BufferEx<BYTE>	_PacketPrefixChars;
#endif

	virtual bool			OnApiInvoke(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp) override;
	bool					OnApiInvokeSwarm(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp);
	void					OnApiInvokeStatus(const rt::String_Ref& arguments, LocalApiResponder* resp);
	itfc::StorageFactory*	_pStorageFactoryByApi = nullptr;

public:
	bool	bWantStop = false;
	bool	bInitializationFinalized = false;

	NetworkServiceCore();
	~NetworkServiceCore();
	const DhtAddress& GetNodeId() const;

	UINT	GetTick() const { return _Tick; }
	
	bool	Start(const rt::String_Ref& node_name, int port, const DhtAddress& DhtAddress, DWORD netsvc_flag, const rt::String_Ref& api_bind = nullptr, LPCSTR dht_bootstrap_file = nullptr, int32_t rcvbufSize = 0);
	bool	Start(const os::CommandLine& cmd, int port = 0);
	bool	StartOnlyLocalServices(DWORD netsvc_flag = NETSVC_CONSOLE|NETSVC_API, const rt::String_Ref& bind = nullptr);

	bool	IsRunning() const;
	void	AwaitShutdown() const;
	void	StopWorkingThreads();
	void	Stop();

	auto&	GetLocalInterfaces() const { return _LocalNetInterfaces; }
	bool	IsDataServiceSuspended() const { return _DataServiceSuspended; }
	void	SuspendDataService(){ _DataServiceSuspended = true; }; // affects GDP/SMB/PBC
	void	ResumeDataService();

	void	SetOnTickCallback(LPVOID obj, const THISCALL_MFPTR& on_tick);  // 100msec tick
	void	UnsetOnTickCallback(LPVOID obj);
	void	SetPacketOnRecvCallBack(BYTE prefix_char, LPVOID obj, const THISCALL_MFPTR& recv);
	void	OnRecv(LPCVOID pData, UINT len, PacketRecvContext& ctx);
	bool	Send(Packet& packet, const NetworkAddress& to, PACKET_SENDING_FLAG flag = PSF_NORMAL)
			{	
#if defined(PLATFORM_DEBUG_BUILD)
				ASSERT(!packet._DataRuined);
				if(flag&PSF_OBFUSCATION)packet._DataRuined = true;
#endif
				return _Send((LPVOID)packet.GetData(), packet.GetLength(), to, flag);
			}
	bool	Send(Packet& packet, const NetworkAddress& to, const NetworkAddress& relay_peer, PACKET_SENDING_FLAG flag = PSF_NORMAL);

	UINT	GetConnectionState() const { return _ConnectionState; }
	UINT	GetNatMappingState() const { return _NatMappingState; }
	void	GetNetStateReport(rt::String& out);
	void	Awaken();

    void						SetCachePath(LPCSTR cache_path);
    const rt::String&			GetCachePath() const { return _CachePath; }
	void						SetNodeName(const rt::String_Ref& n){ _NodeDesc.SetNodeName(n); }
	void						SetAppNames(const rt::String_Ref& appname, LPCSTR dht_ver = nullptr, LPCSTR dht_app_tag = nullptr); // call before Start/Init

	UINT						GetLocalPort() const { return _LocalPort; }
	UINT						GetLocalPortV6() const { return _LocalPortV6; }
	IPv4						GetNatMappedAddress() const { return _NatExternalIP; }
	IPv4						GetExternalAddress() const;
	const IPv6&					GetExternalAddressV6() const;
	DWORD						GetLocalIP(DWORD ip_peer) const;  // return the one of the one in the same subnet
	bool						IsLocalIP(DWORD ip) const { THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces); return _LocalNetInterfaces.GetImmutable().has(ip); }
	bool						IsSubnetIP(DWORD ip) const;
	const NetworkNodeDesc&		GetNodeDesc() const { return _NodeDesc; }
	
	bool						SampleNetworkTime(DWORD nt32, int latency, const PacketRecvContext& ctx); // true if the sample is accepted
	bool						IsNetworkTimeStablized() const;
	LONGLONG					GetNetworkTime() const;
	LONGLONG					GetUpTime() const { return GetTick()*(LONGLONG)NET_TICK_UNIT; }
	bool						HasSufficientPeers() const;

	GossipNetworkTime&			GNT(){ ASSERT(_pGNT); return *_pGNT; }
	MainlineDHT&				DHT(){ ASSERT(_pDHT); return *_pDHT; }
	LocalSwarm&					LSM(){ ASSERT(_pLSM); return *_pLSM; }
	SwarmBroadcast&				SMB(){ ASSERT(_pSMB); return *_pSMB; }
	LocalApi&					API(){ ASSERT(_pAPI); return *_pAPI; }
	GossipDataPropagation&		GDP(){ ASSERT(_pGDP); return *_pGDP; }
	MultiLinkTunnels&			MLT(){ ASSERT(_pMLT); return *_pMLT; }
	MessageRelayCore&			MRC(){ ASSERT(_pMRC); return *_pMRC; }

	const GossipNetworkTime&	GNT() const { ASSERT(_pGNT); return *_pGNT; }
	const MainlineDHT&			DHT() const { ASSERT(_pDHT); return *_pDHT; }
	const LocalSwarm&			LSM() const { ASSERT(_pLSM); return *_pLSM; }
	const SwarmBroadcast&		SMB() const { ASSERT(_pSMB); return *_pSMB; }
	const LocalApi&				API() const { ASSERT(_pAPI); return *_pAPI; }
	const GossipDataPropagation&GDP() const { ASSERT(_pGDP); return *_pGDP; }	
	const MultiLinkTunnels&		MLT() const { ASSERT(_pMLT); return *_pMLT; }
	const MessageRelayCore&		MRC() const { ASSERT(_pMRC); return *_pMRC; }

	bool						HasGNT() const { return _pGNT; }
	bool						HasDHT() const { return _pDHT; }
	bool						HasLSM() const { return _pLSM; }
	bool						HasSMB() const { return _pSMB; }
	bool						HasGDP() const { return _pGDP; }
	bool						HasMLT() const { return _pMLT; }
	bool						HasMRC() const { return _pMRC; }

	bool						HasIPv6() const { return !_SocketV6.IsEmpty(); }
	bool						HasAPI() const { return _pAPI; }

	bool						GetNodeAccessPoints(NodeAccessPoints& out, UINT size_limit = 0xfffffff, UINT swarm = 1); // compact will not return ipv6 local address only public
	void						GetState(NetworkState& ns);
	void						GetBasicState(NetworkStateBasic& ns);
	void						CriticalHalt(); // call when fatal protocol incompatiblity detected, network will shutdown and irrevocable, CORE_CRITICAL_HALT event will be sent
	void						NatHolePunch(const IPv4& ip);

	void						CloakIP(CloakedIPv4& cip) const { os::xxtea_encode(_CloakedIPSecret, &cip, sizeof(cip)); }
	void						CloakIP(CloakedIPv6& cip) const { os::xxtea_encode(_CloakedIPSecret, &cip, sizeof(cip)); }
	bool						UncloakIP(CloakedIPv4& cip) const { os::xxtea_decode(_CloakedIPSecret, &cip, sizeof(cip)); return (*(WORD*)cip.padding) == 0; }
	bool						UncloakIP(CloakedIPv6& cip) const { os::xxtea_decode(_CloakedIPSecret, &cip, sizeof(cip)); return ((*(DWORD*)cip.padding)&0xffffffU) == 0; }
};

namespace _details
{
extern bool LoadNetworkAddressTable(LPCSTR fn, rt::BufferEx<NetworkAddress>& out, NETADDR_TYPE type = NADDRT_NULL);
extern bool LoadSwarmNetworkAddressTable(LPCSTR fn, ext::fast_map<NetworkAddress, NetworkAddress>& out, uint32_t max_size = 0);
extern bool SaveNetworkAddressTable(LPCSTR fn, const rt::BufferEx<NetworkAddress>& in);
extern bool SaveSwarmNetworkAddressTable(LPCSTR fn, const ext::fast_map<NetworkAddress, NetworkAddress>& in);
} // namespace _details

} // namespace upw

