#include "../externs/miniposix/core/os/thread_primitive.h"
#include "../externs/miniposix/core/rt/json.h"
#include "netsvc_core.h"
#include "local_swarm.h"
#include "swarm_broadcast.h"
#include "gossip_nettime.h"
#include "nat_passthrough.h"
#include "./dht/dht.h"
#include "./gdp/gdp.h"
#include "./mrc/mrc.h"
#include "./mlt/mlt.h"
#include "./api/local_api.h"


// consider header obfuscation and pretending other UDP applications
// SNMP:		30 2C 02 01
// RIP:			02 01 00 00
// DHCP:		01 01 06 00
// RTP(H263):	12 44 rr rr

namespace upw
{
namespace _details
{
enum cloaking_header : uint16_t
{
	CLOAKING_HEADER_SNMP	= 0x2c30,
	CLOAKING_HEADER_RIP		= 0x0102,
	CLOAKING_HEADER_DHCP	= 0x0101,
	CLOAKING_HEADER_RTP		= 0x4412
};

static const WORD CLOAKING_HEADER_IPSIG = CLOAKING_HEADER_RTP;
static const WORD CLOAKING_HEADER = CLOAKING_HEADER_SNMP;

inline void _ObfuscateTransform(DWORD seed, LPBYTE p, UINT len)
{
	LPBYTE p_end = p - len;
	while(p + 4 <= p_end)
	{
		(*(DWORD*)p) ^= seed;
		p += 4;
	}

	if(p>=p_end)return;
	*p++ ^= seed; 	seed>>=8;
	
	if(p>=p_end)return;
	*p++ ^= seed; 	seed>>=8;

	if(p>=p_end)return;
	*p++ ^= seed; 	seed>>=8;
}
} // namespace _details

NetworkServiceCore::NetworkServiceCore()
#if defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	:_Socket(*this)
	,_SocketV6(*this)
#endif
{
	DEF_COREEVENTS_BEGIN(MODULE_CORE)
		DEF_COREEVENT(CORE_TICK)
		DEF_COREEVENT(CORE_EXIT)
		DEF_COREEVENT(CORE_CRITICAL_HALT)
	DEF_COREEVENTS_END

	DEF_COREEVENTS_BEGIN(MODULE_NETWORK)
		DEF_COREEVENT(NETWORK_CONNECTIVITY_CHANGED)
		DEF_COREEVENT(NETWORK_ADDRESS_CHANGED)
		DEF_COREEVENT(NETWORK_LOCAL_SWARM_CHANGED)
		DEF_COREEVENT(NETWORK_SWARM_CHANGED)
		DEF_COREEVENT(NETWORK_TIME_STABLIZED)
		DEF_COREEVENT(NETWORK_LOCATION_CHANGED)
		DEF_COREEVENT(NETWORK_MULTILINK_BUSY)
		DEF_COREEVENT(NETWORK_MULTILINK_IDLE)
		DEF_COREEVENT(NETWORK_GDP_PRIORITY_BUSY)
		DEF_COREEVENT(NETWORK_GDP_PRIORITY_IDLE)
	DEF_COREEVENTS_END

	bWantStop = false;
	//rt::Zero(_OnRecvPacket);
    memset(_OnRecvPacket, 0, 256 * sizeof(_CallbackItem));

#if !defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	_RecvThreads.SetSize(os::GetNumberOfPhysicalProcessors() * 2);
#endif

	_pGNT = nullptr;
	_pDHT = nullptr;
	_pSMB = nullptr;
	_pLSM = nullptr;
	_pAPI = nullptr;
	_pGDP = nullptr;
	_pMLT = nullptr;
	_pMRC = nullptr;

	_LocalPort = 0;
	_LocalPortV6 = 0;

	_IsInterfacesReconfiging = false;

	rt::Zero(_NatExternalIPV6);
	rt::Zero(_NatExternalIP);
	_NatInternalIP = 0;
	rt::Zero(_NatInternalIPV6);

	_NatMappingState = LNS_NOOP;
	_ConnectionState = NCS_DISCONNECTED;
	_NodeDesc.ServicesActivated = 0;

	rt::Zero(_OnTick);
	_OnTickCBCount = 0;

	_CachePath = ".";
}

bool NetworkServiceCore::SampleNetworkTime(DWORD nt32, int latency, const PacketRecvContext& ctx)
{
	if(_pGNT)return _pGNT->OnPeerTimeSample(nt32, latency, ctx);
	return false;
}

LONGLONG NetworkServiceCore::GetNetworkTime() const
{
	return (_pGNT && _pGNT->IsAvailable())?_pGNT->GetTime():os::Timestamp::Get();
}

void NetworkServiceCore::CriticalHalt()
{
	StopWorkingThreads();

	_NatMappingState = LNS_SOLVING;
	_ConnectionState = NCS_DISCONNECTED;

	CoreEvent(MODULE_CORE, CORE_CRITICAL_HALT);
}

bool NetworkServiceCore::IsNetworkTimeStablized() const
{
	return _pGNT == nullptr || _pGNT->IsStablized();
}

bool NetworkServiceCore::Start(const os::CommandLine& cmd, int port)
{
	_LOGC("[NET]: OXD/Network startup: " + rt::tos::Timestamp<>(os::Timestamp::Get()));

    DWORD flag = 0;
    if(cmd.HasOption("genesis"))flag |= NETSVC_GNT_GENESIS;

    if(cmd.HasOption("dht"))flag |= NETSVC_DHT;
    if(cmd.HasOption("gnt"))flag |= NETSVC_GNT;
    if(cmd.HasOption("nat"))flag |= NETSVC_NAT;
    if(cmd.HasOption("lsm"))flag |= NETSVC_LSM;
    if(cmd.HasOption("smb"))flag |= NETSVC_SMB;
    if(cmd.HasOption("gdp"))flag |= NETSVC_GDP;
    if(cmd.HasOption("api"))flag |= NETSVC_API;
	if(cmd.HasOption("pbc"))flag |= NETSVC_PBC;
	if(cmd.HasOption("hob"))flag |= NETSVC_HOB;
	if(cmd.HasOption("mlt"))flag |= NETSVC_MLT;
	if(cmd.HasOption("mrc"))flag |= NETSVC_MRC;
#if !defined(PLATFORM_IOS) && !defined(PLATFORM_ANDROID)
    if(cmd.HasOption("con"))flag |= NETSVC_API|NETSVC_CONSOLE;
#endif

	rt::String_Ref api_bind = cmd.GetOption("api");

	if(flag&NETSVC_MASK_NONLOCAL)
	{
		rt::String name;
		os::GetHostName(name);
		rt::String_Ref n = cmd.GetOption("name", name);
		_LOGC_VERBOSE("[NET]: Service Node Name: "<<n);

		DhtAddress addr;
		if(!addr.FromString(cmd.GetOption("dht")))
			addr.Random();

		if(port == 0)
			port = (rt::Randomizer(os::TickCount::Get()).GetNext()%30000) + 2048;
            
		if(Start(n, cmd.GetOptionAs<int>("port", port), addr, flag, api_bind, nullptr, cmd.GetOptionAs<int32_t>("udp_rcvbuf_size", 0)))
			return true;
	}
	else
	{
		if(StartOnlyLocalServices(flag, api_bind))
			return true;
	}

	_LOG_ERROR("Failed to start network service core");
	return false;
}

bool NetworkServiceCore::_StartLocalServices(const rt::String_Ref& bind)
{
	if(_TickingThread.IsRunning())return true;

	if((_NodeServiceActivated&NETSVC_API) && !_pAPI)
	{
		VERIFY(_pAPI = _New(LocalApi(this)));

		int flag = LocalApi::PROTO_HTTP|LocalApi::PROTO_WEBSOCKET;

#if !defined(PLATFORM_IOS) && !defined(PLATFORM_ANDROID) && !defined(PLATFORM_DISABLE_LOG)
		if(NETSVC_CONSOLE&_NodeServiceActivated)
			flag |= LocalApi::PROTO_CONSOLE;
#endif

		if(!_pAPI->Init(flag, bind))return false;

		_pAPI->SetCommandExtension("net", this, &NetworkServiceCore::_OnExecuteCommand);
		_pAPI->SetApiHandler("core", this);
		if(HasDHT())
			_pAPI->SetApiHandler("swarm", this);
	}

	struct _call
	{	static DWORD _itrfunc(LPVOID p)
		{	((NetworkServiceCore*)p)->_Ticking();
			return 0;
		}
	};

	if(!_TickingThread.Create(_call::_itrfunc, this))
		return false;

	return true;
}

void NetworkServiceCore::AwaitShutdown() const
{
	while(!bWantStop)os::Sleep(1000);
}

bool NetworkServiceCore::StartOnlyLocalServices(DWORD netsvc_flag, const rt::String_Ref& bind)
{
	rt::Zero(_NatExternalIPV6);
	rt::Zero(_NatExternalIP);
	_NatInternalIP = 0;
	_LocalPort = 0;
	rt::Zero(_NatInternalIPV6);

	_NatMappingState = LNS_UNNECESSARY;
	_ConnectionState = NCS_PRIVATE_NETWORK;
	_NodeServiceActivated = netsvc_flag&(NETSVC_CONSOLE|NETSVC_API);
	rt::Zero(_NodeDesc);

	if(!_StartLocalServices(bind))
		return false;

	bWantStop = false;
	return true;
}

bool NetworkServiceCore::Start(const rt::String_Ref& node_name, int port, const DhtAddress& DhtAddress, DWORD netsvc_flag, const rt::String_Ref& api_bind, LPCSTR dht_bootstrap_file, int32_t rcvbufSize)
{
	bInitializationFinalized = false;
	bWantStop = false;
	sec::Randomize(_CloakedIPSecret);
	_DataServiceSuspended = NETSVC_DATA_SERVICE_SUSPENDED&netsvc_flag;

	rt::Zero(_NatExternalIPV6);
	rt::Zero(_NatExternalIP);
	_NatInternalIP = 0;
	rt::Zero(_NatInternalIPV6);

#if defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	ASSERT(!_UdpPump.IsRunning());
#else
	ASSERT(!_RecvThreads[0].IsRunning());
	__ThreadId = -1;
#endif

	_LocalPort = port;
	_LocalPortV6 = port?port + 1:0;
	_RcvbufSize = rcvbufSize;

	_NatMappingState = LNS_SOLVING;
	_ConnectionState = NCS_DISCONNECTED;

	_NodeServiceActivated = netsvc_flag;

	_NodeDesc.ServicesActivated = (netsvc_flag&NETSVC_MASK_REPORTING);
	_NodeDesc.SetNodeName(node_name);
	_NodeDesc.LocalTime32 = 0;

#if defined(OXD_SIMULATE_RESTRICTED_NETWORK)
	_NodeServiceActivated &= (~NETSVC_LSM);
	_NodeDesc.ServicesActivated &= (~NETSVC_LSM);
#endif

#if defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	if(!_UdpPump.Init(0, NET_DATAGRAMNETWORK_MTU))
	{
		_LOG_ERROR("[NET]: failed to start Event-driven UDP pump");
		goto FAILED_START;
	}

	if(!_Socket.Create(_LocalPort, false, _RcvbufSize))
		goto FAILED_START;

    _LocalPort = _Socket.GetBindPort();
    _UdpPump.AddObject(&_Socket);

    if(_SocketV6.Create(_LocalPortV6, true, _RcvbufSize))
    {		
        _LocalPortV6 = _SocketV6.GetBindPort();
        _UdpPump.AddObject(&_SocketV6);
    }
#else
	struct _call
	{	static DWORD _func(LPVOID p)
		{	((NetworkServiceCore*)p)->_RecvThreadFunc();
			return 0;
		}
	};

	for(UINT i=0;i<_RecvThreads.GetSize();i++)
		if(!_RecvThreads[i].Create(_call::_func, this))
			goto FAILED_START;
#endif

	os::Sleep(NET_TICK_UNIT);

	if(_NodeDesc.HasDHT())
	{
		VERIFY(_pDHT = _New(MainlineDHT(this, DhtAddress, _NodeDesc)));
		if(dht_bootstrap_file)
			_pDHT->SetStockBootstrapFile(dht_bootstrap_file);

		_pDHT->ForceRefresh();
	}

	if(_NodeDesc.HasLSM())
		VERIFY(_pLSM = _New(LocalSwarm(this, _NodeDesc, NET_LOCALSWRAM_EXPECTED_PEER_COUNT)));

	_UpdateLocalAddress(true);

	if(_NodeDesc.HasGNT())
	{	
		VERIFY(_pGNT = _New(GossipNetworkTime(this)));
		if(NETSVC_GNT_GENESIS&netsvc_flag)
			_pGNT->Reset(true);
	}

	if(_NodeDesc.HasDHT() || _NodeDesc.HasLSM() || (netsvc_flag&NETSVC_SMB))
	{
		VERIFY(_pSMB = _New(SwarmBroadcast(this)));
		_NodeDesc.ServicesActivated |= NETSVC_SMB;
	}

	if(_NodeDesc.HasGDP() && HasSMB())
	{	
		VERIFY(_pGDP = _New(GossipDataPropagation(this)));
	}
	else
	{	_NodeDesc.ServicesActivated = _NodeDesc.ServicesActivated & (~NETSVC_GDP);
	}

	if(_NodeDesc.HasMRC() && HasSMB())
	{
		VERIFY(_pMRC = _New(MessageRelayCore(this)));
	}
	else
	{	_NodeDesc.ServicesActivated = _NodeDesc.ServicesActivated & (~NETSVC_MRC);
	}

	if(!_StartLocalServices(api_bind))
		goto FAILED_START;

	if(_NodeDesc.HasMLT())
	{
		VERIFY(_pMLT = _New(MultiLinkTunnels(this)));
	}
	else
	{
		_NodeDesc.ServicesActivated = _NodeDesc.ServicesActivated & (~NETSVC_MLT);
	}

    ASSERT(!bWantStop);
	return true;

FAILED_START:
	Stop();
	return false;
}

void NetworkServiceCore::StopWorkingThreads()
{
#if defined(PLATFORM_IOS)
	UINT time_wait = 10;
#else
	UINT time_wait = INFINITE;
#endif

	bWantStop = true;

#if !defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	__ThreadId = -1;
	_CloseAllSockets();

	if(_RecvThreads.GetSize())
	{
		for(UINT i=0;i<_RecvThreads.GetSize();i++)
			_RecvThreads[i].WaitForEnding(time_wait, true);
	}
#else
	_UdpPump.Term();
	_CloseAllSockets();
#endif

	{	EnterCSBlock(_DetermineConnectionThreadsCS);
		for(auto it : _DetermineConnectionThreads)
			it->WantExit() = true;
	}

	if(_TickingThread.IsRunning())
	{
		_TickingThread.WantExit() = true;
		_TickingThread.WaitForEnding(time_wait, true);
	}

#if defined(PLATFORM_IOS)
	for(auto& t : _DetermineConnectionThreads)
	{
		if(t)
		{	
			t->TerminateForcely();
			_SafeDel_ConstPtr(t);
		}
	}
	_DetermineConnectionThreads.clear();
#else
	for(;;)
	{
		{	EnterCSBlock(_DetermineConnectionThreadsCS);
			if(_DetermineConnectionThreads.size() == 0)
				break;
		}

		os::Sleep(100);
	}
#endif

#if !defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	_RecvThreads.SetSize(0);
#endif

	_LocalPort = 0;
	_LocalPortV6 = 0;

	_NatMappingState = LNS_SOLVING;
	_SetConnectionState(NCS_DISCONNECTED);
	_NodeDesc.ServicesActivated = 0;

	_OnTickCBCount = 0;
}

void NetworkServiceCore::Stop()
{
	StopWorkingThreads();

	_NatMappingState = LNS_SOLVING;
	_ConnectionState = NCS_DISCONNECTED;

	CoreEvent(MODULE_NETWORK, NETWORK_CONNECTIVITY_CHANGED);

	// rt::Zero(_OnRecvPacket);
    memset(_OnRecvPacket, 0, 256 * sizeof(_CallbackItem));
	rt::Zero(_OnTick);

	_SafeDel(_pMLT);
	_SafeDel(_pMRC);

	_SafeRelease(_pStorageFactoryByApi);

	_SafeDel(_pGDP);
	_SafeDel(_pSMB);
	_SafeDel(_pGNT);
	_SafeDel(_pLSM);
	_SafeDel(_pDHT);

	bInitializationFinalized = false;
}

NetworkServiceCore::~NetworkServiceCore()
{
	Stop();
	_SafeDel(_pAPI);
}

bool NetworkServiceCore::IsRunning() const
{
	return _TickingThread.IsRunning();
}

void NetworkServiceCore::SetCachePath(LPCSTR cache_path)
{
    os::File::ResolveRelativePath(cache_path, _CachePath);
    os::File::CreateDirectories(_CachePath);
    
    if(!os::File::IsDirectory(_CachePath))
        _LOG_WARNING("[NET]: Core cache is not a directory: "<<_CachePath);
}

void NetworkServiceCore::GetNetStateReport(rt::String& out)
{
    static const char LN = '\n';
	if(_ConnectionState == NCS_DISCONNECTED)
	{
		out += rt::SS("*** All Local Networks are Disconnected ***");
		return;
	}

	out += rt::SS("*** Network State Report ***") + LN;

	switch(_ConnectionState)
	{
	case NCS_PUBLIC_NETWORK: out += rt::SS("Public Network: "); break;
	case NCS_PRIVATE_NETWORK: out += rt::SS("Private Network: "); break;
	case NCS_PRIVATE_INTRANET: out += rt::SS("Private Intranet: "); break;
	default: ASSERT(0);
	}

	out += tos(GetExternalAddress());
	if(_NatInternalIP)
		out += rt::SS(" (") + tos(_NatInternalIP) + ')';
	else
	{
		THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
		auto& local_ip = _LocalNetInterfaces.GetImmutable();
		if(local_ip.size())
		{
			IPv4 a;
			a.IP = local_ip.begin()->second.LocalIP;
			a.SetPort(_LocalPort);
			out += rt::SS(" (") + tos(a) + ')';
		}
	}

	out += LN;
	auto& ipv6 = GetExternalAddressV6();
	out += rt::SS("IPv6:");
	if(HasIPv6() && !ipv6.IsEmpty())
	{
		out += tos(GetExternalAddressV6());
		if(((uint64_t*)_NatInternalIPV6)[0] != 0 || ((uint64_t*)_NatInternalIPV6)[1] != 0)
			out += rt::SS(" (") + tos(_NatInternalIPV6) + ')';
	}
	else
		out += "off";

	out += rt::SS(" Tick:") + _Tick + LN;

	if(_pDHT)
	{	out += rt::SS("DHT:") + _pDHT->GetRoutingTableSize() + ' ';
	}
	else
	{	out += rt::SS("DHT:off ");
	}

	if(_pLSM)
	{	out += rt::SS("LSM:") + _pLSM->GetSwarmSize() + ' ';
	}
	else
	{	out += rt::SS("LSM:off ");
	}

	out += rt::SS("GNT:") + ((NETSVC_GNT&_NodeServiceActivated)?rt::SS("on"):rt::SS("off")) + ' ';
	out += rt::SS("GDP:") + ((NETSVC_GDP&_NodeServiceActivated)?rt::SS("on"):rt::SS("off")) + ' ';
	out += rt::SS("PBC:") + ((NETSVC_PBC&_NodeServiceActivated)?rt::SS("on"):rt::SS("off")) + ' ';
	out += rt::SS("HOB:") + ((NETSVC_HOB&_NodeServiceActivated)?rt::SS("on"):rt::SS("off")) + ' ';
	out += rt::SS("MLT:") + ((NETSVC_MLT&_NodeServiceActivated)?rt::SS("on"):rt::SS("off")) + ' ';

	out += LN;

	if(_pAPI)
	{	
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
		int p = _pAPI->GetJsonRpcPort();
		if(p)
			out += rt::SS("API:") + p + "/RPC ";
		else
#endif
			out += rt::SS("API:on ");
	}
	else
	{	out += rt::SS("API:off ");
	}

	out += rt::SS("NAT:");

	if(_NodeServiceActivated&NETSVC_NAT)
	{	
		switch(_NatMappingState)
		{
		case LNS_NOOP:
			out += rt::SS("n/a");
			break;
		case LNS_MAPPING:
			out += rt::SS("mapping");
			break;
		case LNS_SOLVING:
			out += rt::SS("resolving");
			break;
		case LNS_MAPPED:
			if(_pDHT && _pDHT->IsPublicAddressAvailable() && _pDHT->GetPublicAddress().Port() == _NatExternalIP.Port())
				out += rt::SS("mapped/WAN");
			else
				out += rt::SS("mapped/LAN");
			break;
		case LNS_UNMAPPED:
			out += "failed";
			break;
		case LNS_UNNECESSARY:
			out += "on";
			break;
		}
	}
	else
	{	out += rt::SS("off");
	}

	out += LN;

	{	LONGLONG nt = GetNetworkTime();
		out += rt::SS("NetTime: ") + rt::tos::Timestamp<>(nt) + " (" + nt + ')';

		if(_pGNT)
		{
			out += rt::SS("\n(D/V=") + _pGNT->GetTimeDrift() + '/' + _pGNT->GetTimeDriftVariance() + ')';

			if(!_pGNT->IsStablized())
			{
				out += rt::SS(" - Resolving");
			}
			else
			{
				if(_pGNT->IsCasting())
					out += rt::SS(" - Casting S=") + _pGNT->GetStablizationDegree();
			}
		}

		out += LN;
	}

#if defined(PLATFORM_WIN) && defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
	out += rt::SS("Outstanding RecvFrom: ") + _UdpPump._PendingRecvCall + LN;
#endif

#if defined(PLATFORM_DEBUG_BUILD)
	out += LN;
	out += rt::SS("*** Packet PrefixChar State Report ***") + LN;
	if(_PacketPrefixChars.GetSize())
	{
		for(uint32_t i = 0; i < _PacketPrefixChars.GetSize(); i++)
		{
			auto prefix = _PacketPrefixChars[i];
			out += rt::SS("PrefixChar:[") + (char)prefix + ']' + LN;

			ULONGLONG total_recv = _PacketState[prefix].TotalRecvBytes;
			ULONGLONG total_sent = _PacketState[prefix].TotalSentBytes;
			out += rt::String_Ref() + 
				   rt::SS("I/O: ") + 
				   rt::tos::FileSize<true,true>(total_recv) + rt::SS(" + ") + 
				   rt::tos::FileSize<true,true>(total_sent) + rt::SS(" = ") +
				   rt::tos::FileSize<true,true>(total_recv+total_sent) + 
				   LN +
				   rt::SS("PKT: ") + 
				   _PacketState[prefix].TotalRecvPacket + rt::SS(" + ") + 
				   _PacketState[prefix].TotalSentPacket + rt::SS(" = ") + 
				   (_PacketState[prefix].TotalRecvPacket + _PacketState[prefix].TotalSentPacket) + 
				   LN;
			out += LN;
		}
	}
#endif

	if(_pDHT)
	{	out += LN;
		_pDHT->GetStateReport(out);
	}
    
	if(_pLSM)
    {   if(_pDHT)out += LN;
        _pLSM->GetStateReport(out);
	}
}

namespace _details
{
template<typename AddrType>
bool CreateSocket(AddrType& bind, inet::Socket &newSocket, UINT &socketPort, int32_t rcvbufSize)
{
	LPCSTR ip_ver = sizeof(AddrType) == sizeof(inet::InetAddr)?"ipv4":"ipv6";
	newSocket.Close();

	int port_base = socketPort;
	for(UINT i = 0; i < 100; i++)
	{
		bind.SetPort(socketPort = i + port_base);
		if(newSocket.Create(bind, SOCK_DGRAM, 0))
		{
//#if defined(PLATFORM_IOS) || defined(PLATFORM_MAC) // iOS, Mac has an undocumented size limit of the buffer, 3MB seams ok, but 4MB fails
//			VERIFY(newSocket.SetBufferSize(3 * 1024 * 1024, true));
//			//VERIFY(newSocket.SetBufferSize(3 * 1024 * 1024, false));
//#else
//			VERIFY(newSocket.SetBufferSize(4 * 1024 * 1024, true));
//			//VERIFY(newSocket.SetBufferSize(4 * 1024 * 1024, false));
//#endif
			if(rcvbufSize != 0)
				VERIFY(newSocket.SetBufferSize(rcvbufSize));  // set reveive buffer size

			AddrType actual_bind;
			newSocket.GetBindName(actual_bind);
			socketPort = actual_bind.GetPort();

			_LOGC_VERBOSE("[NET]: Primary I/O Socket ("<<ip_ver<<") created on "<<rt::tos::ip(actual_bind));
			if(rcvbufSize != 0)
				_LOGC_VERBOSE("[NET]: Primary I/O Socket " << rt::tos::ip(actual_bind) << " ("<<ip_ver<<") receive buffer size set to "<< rcvbufSize << " bytes");
			return true;
		}
		else
		{
			_LOGC_VERBOSE("[NET]: Primary I/O Socket ("<<ip_ver<<") creation failed ("<<newSocket.GetLastError()<<") on "<<rt::tos::ip(bind));
		}
	}

	return false;
}
} // namespace _details


#if !defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
void NetworkServiceCore::_RecvThreadFunc()
{
	os::Thread::SetLabel(NET_RECV_THREAD_LABEL);

	INT tid = os::AtomicIncrement(&__ThreadId);

	while(__ThreadId>=0 && !bWantStop)
	{
		if(tid % 2 == 1)
		{
			while(_SocketV6.IsEmpty() && !bWantStop)
			{
				if(tid == 1)
				{

                    inet::InetAddrV6 bind[8];
                    bind[0].SetAsAny();
                       
					// On iPhone WIFI will usually have a IPv6 but not connect to Internet
					// but iOS mistakenly prefers routing to WIFI than cellular network
					// So we explicitly bind to cellular network interface instead to any_address
#if defined(PLATFORM_IOS)
                    GetLocalAddresses(bind, 8, true, nullptr, "pdp_ip0,pdp_ip1");
#endif
					if(_details::CreateSocket<inet::InetAddrV6>(bind[0], _SocketV6, _LocalPortV6, _RcvbufSize))
						break;

					//InetAddrV6 bind;
					//bind.SetAsAny();
					//if(_details::CreateSocket<inet::InetAddrV6>(bind, _SocketV6, _LocalPortV6))
					//	break;
                    
					os::Sleep(3900, &bWantStop);
				}

				os::Sleep(900, &bWantStop);
			}

			while(!_SocketV6.IsEmpty())
			{
				BYTE buf[NET_DATAGRAMNETWORK_MTU + 64];

				inet::InetAddrV6 from;
				UINT recved = 0;
				if(_SocketV6.RecvFrom(buf, sizeof(buf), recved, from) && recved)
				{
					if(from.IsLoopback())
						continue; // drop self-sending

					PacketRecvContext ctx;
					ctx.RecvFrom.IPv6().Set(from);

					// Call OnRecv   
					OnRecv(buf, recved, ctx);
				}
				else
				{
					if(__ThreadId < 0)return;
					if(_SocketV6.IsErrorUnrecoverable(inet::Socket::GetLastError()))
					{
						if(tid == 1)
						{
							_LOGC_WARNING("[NET]: Primary I/O Socket Error=" << _SocketV6.GetLastError() << ", retry binding");
							_SocketV6.Close();
						}

						os::Sleep(100);
					}
				}
			}
		}
		else
		{
			while(_Socket.IsEmpty() && !bWantStop)
			{
				if(tid == 0)
				{
                    inet::InetAddr bind;
                    bind.SetAsAny();
					if(_details::CreateSocket<inet::InetAddr>(bind, _Socket, _LocalPort, _RcvbufSize))
						break;

					os::Sleep(3900, &bWantStop);
				}

				os::Sleep(900, &bWantStop);
			}

			while(!_Socket.IsEmpty())
			{
				BYTE buf[NET_DATAGRAMNETWORK_MTU + 32];

				inet::InetAddr from;
				UINT recved = 0;
				if(_Socket.RecvFrom(buf, sizeof(buf), recved, from) && recved)
				{
					if((_LocalPort == from.GetPort() && IsLocalIP(*((DWORD*)from.GetBinaryAddress()))) || from.IsLoopback())
						continue; // drop self-sending

					PacketRecvContext ctx;
					ctx.RecvFrom.IPv4().Set(from);

					// Call OnRecv   
					OnRecv(buf, recved, ctx);
				}
				else
				{
					if(__ThreadId < 0)return;
					if(_Socket.IsErrorUnrecoverable(inet::Socket::GetLastError()))
					{
						if(tid == 0)
						{
							_LOGC_WARNING("[NET]: Primary I/O Socket Error=" << _Socket.GetLastError() << ", retry binding");
							_Socket.Close();
						}

						os::Sleep(100);
					}
				}
			}
		}
	}
}
#endif


#if defined(NET_USE_EVENTDRIVEN_SOCKET_IO)
bool NetworkServiceCore::UdpSocket::Create(int port_base, bool ip_v6, int32_t rcvbufSize)
{
	Port = port_base;
	V6 = ip_v6;
	RcvbufSize = rcvbufSize;

	if(ip_v6)
	{
#if defined(PLATFORM_IOS)
        inet::InetAddrV6 addr[8];
        if(GetLocalAddresses(addr, 8, true, nullptr, "pdp_ip0,pdp_ip1") == 0) // try if cellular network
            addr[0].SetAsAny();
        return _details::CreateSocket(addr[0], *this, Port, RcvbufSize);
#else
        inet::InetAddrV6 addr;
        addr.SetAsAny();
        return _details::CreateSocket(addr, *this, Port, RcvbufSize);
#endif

	}
	else
	{
		inet::InetAddr addr;
		addr.SetAsAny();
		return _details::CreateSocket(addr, *this, Port, RcvbufSize);
	}
}
#endif

namespace _details
{

inline BYTE quick_sig(LPCBYTE p, UINT len)
{
	return len * p[0] + p[len/2] + p[len-1];
}

};

void NetworkServiceCore::OnRecv(LPCVOID pData, UINT len, PacketRecvContext& ctx)
{
	ASSERT(pData);
	if(len == 0)return;

	LPBYTE buf = (LPBYTE)pData;

#if defined(OXD_SIMULATE_RESTRICTED_NETWORK)
	if(buf[0] == 'd')return;
#endif

	PacketRecvContext ctx_replaced;
	PacketRecvContext* pctx = &ctx;
	PACKET_SENDING_FLAG forward_flag = PSF_NORMAL;  // effects forwarding

	if(buf[0] <= NET_PACKET_OBFUSCATION_MAXHEADBYTE)
	{
		forward_flag |= PSF_OBFUSCATION;

		if(len <= 3)return; // discards
		const WORD& head = *(WORD*)buf;
		if(head == _details::CLOAKING_HEADER)
		{
			// CLOAKING_HEADER       [cloak_header:2B][xor data(len*(len<<10 + len)]
			buf += 2;
			len -= 2;
			_details::_ObfuscateTransform(len*((len<<10) + len), buf, len);
		}
		else if(len > 6 && head == _details::CLOAKING_HEADER_IPSIG)
		{
			// CLOAKING_HEADER_IPSIG [cloak_header:2B][IP_Sig:4B][xor data(IP_Sig)]
			DWORD ip_sig = ctx.RecvFrom.GetAddressSignature();
			if(ip_sig == *(DWORD*)(buf+2))
				forward_flag |= PSF_IP_RESTRICTED_VERIFIED;
			buf += 6;
			len -= 6;
			_details::_ObfuscateTransform(ip_sig, buf, len);
		}
		else
		{
			return;
		}
	}

	if(IsDataServiceSuspended())
	{
		if(	buf[0] == NET_FORWARD_PACKET_HEADBYTE_V6 ||	// PBC forwarding
			buf[0] == NET_FORWARD_PACKET_HEADBYTE_V4 || // PBC forwarding
			buf[0] == NET_PACKET_HEADBYTE_GDP ||
			buf[0] == NET_PACKET_HEADBYTE_LSM_BROADCAST
		)return;
	}

	if(!ctx.pRelayPeer)
	{
		// packet bounce (forward -> relay)
		if(NETSVC_PBC&_NodeServiceActivated)
		{
			if(buf[0] == NET_FORWARD_PACKET_HEADBYTE_V6)
			{
				if(_SocketV6.IsValid())
				{
					NetworkAddress to;
					to.IPv6() = *((IPv6*)&buf[len-sizeof(IPv6)]);

					if(ctx.RecvFrom.Type() == NADDRT_IPV4)
					{
						*(IPv4*)&buf[len-sizeof(IPv6)] = ctx.RecvFrom.IPv4();
						buf[0] = NET_RELAY_PACKET_HEADBYTE_V4;

						_Send(buf, len - (sizeof(IPv6) - sizeof(IPv4)), to, (PACKET_SENDING_FLAG)forward_flag);
					}
					else
					{	ASSERT(ctx.RecvFrom.Type() == NADDRT_IPV6);
						*(IPv6*)&buf[len-sizeof(IPv6)] = ctx.RecvFrom.IPv6();
						buf[0] = NET_RELAY_PACKET_HEADBYTE_V6;

						_Send(buf, len, to, (PACKET_SENDING_FLAG)forward_flag);
					}
				}

				return;
			}
			else if(buf[0] == NET_FORWARD_PACKET_HEADBYTE_V4)
			{
				if(_Socket.IsValid())
				{
					NetworkAddress to;
					to.IPv4() = *((IPv4*)&buf[len-sizeof(IPv4)]);

					if(ctx.RecvFrom.Type() == NADDRT_IPV4)
					{
						*(IPv4*)&buf[len-sizeof(IPv4)] = ctx.RecvFrom.IPv4();
						buf[0] = NET_RELAY_PACKET_HEADBYTE_V4;

						_Send(buf, len, to, (PACKET_SENDING_FLAG)forward_flag);
					}
					else
					{	ASSERT(ctx.RecvFrom.Type() == NADDRT_IPV6);
						*(IPv6*)&buf[len-sizeof(IPv4)] = ctx.RecvFrom.IPv6();
						buf[0] = NET_RELAY_PACKET_HEADBYTE_V6;

						_Send(buf, len + (sizeof(IPv6) - sizeof(IPv4)), to, (PACKET_SENDING_FLAG)forward_flag);
					}
				}

				return;
			}
		}

		// decompose relay packet
		if(buf[0] == NET_RELAY_PACKET_HEADBYTE_V6)
		{
			ctx_replaced.RecvFrom.IPv6() = *(IPv6*)&buf[len-sizeof(IPv6)];
			ctx_replaced.pRelayPeer = &ctx.RecvFrom;
			ctx_replaced.SendingFlag = ctx.SendingFlag;
			pctx = &ctx_replaced;

			buf++;
			len -= 1 + sizeof(IPv6);
		}
		else
        if(buf[0] == NET_RELAY_PACKET_HEADBYTE_V4)
		{
			ctx_replaced.RecvFrom.IPv4() = *(IPv4*)&buf[len-sizeof(IPv4)];
			ctx_replaced.pRelayPeer = &ctx.RecvFrom;
			ctx_replaced.SendingFlag = ctx.SendingFlag;
			pctx = &ctx_replaced;
			
			buf++;
			len -= 1 + sizeof(IPv4);
		}
	}
	else
	{
		ASSERT(buf[0] > NET_FORWARD_PACKET_HEADBYTE_V4);
		if(buf[0] <= NET_FORWARD_PACKET_HEADBYTE_V4)
			return;
	}

	pctx->SendingFlag |= forward_flag;

	if(len)
	{
		auto& item = _OnRecvPacket[*buf];

		if(item.Obj)
		{
#if defined(PLATFORM_DEBUG_BUILD)
			if(_PacketState[buf[0]].IsSet)
			{
				auto& state = _PacketState[buf[0]];
				os::AtomicAdd(len, &state.TotalRecvBytes);
				os::AtomicIncrement(&state.TotalRecvPacket);
			}
#endif
			THISCALL_POLYMORPHISM_INVOKE(OnRecv, item.Obj, item.Func, buf, len, *pctx);
		}
		else
		{	// call fallback
		}
	}
}

void NetworkServiceCore::SetOnTickCallback(LPVOID obj, const THISCALL_MFPTR& on_tick)
{
	ASSERT(_OnTickCBCount < sizeofArray(_OnTick));

	_OnTick[_OnTickCBCount].Obj = obj;
	_OnTick[_OnTickCBCount].Func = on_tick;

	_OnTickCBCount++;

	if(obj)
		THISCALL_POLYMORPHISM_INVOKE(OnTick, obj, on_tick, _Tick, GetNetworkTime());
}

void NetworkServiceCore::UnsetOnTickCallback(LPVOID obj)
{
	int max_cb = -1;
	for(UINT i=0; i<_OnTickCBCount; i++)
	{
		if(_OnTick[i].Obj == obj)
			_OnTick[i].Obj = nullptr;
		else
			max_cb = i;
	}

	_OnTickCBCount = max_cb + 1;
}

void NetworkServiceCore::SetPacketOnRecvCallBack(BYTE prefix_char, LPVOID obj, const THISCALL_MFPTR& recv)
{
	ASSERT(NET_PACKET_OBFUSCATION_MAXHEADBYTE < prefix_char); // these are reserved
	ASSERT(NET_RELAY_PACKET_HEADBYTE_V4 != prefix_char);   // this is reserved
	ASSERT(NET_RELAY_PACKET_HEADBYTE_V6 != prefix_char);   // this is reserved
	ASSERT(NET_FORWARD_PACKET_HEADBYTE_V4 != prefix_char);   // this is reserved
	ASSERT(NET_FORWARD_PACKET_HEADBYTE_V6 != prefix_char);   // this is reserved

	auto& item = _OnRecvPacket[(UINT)prefix_char];

	if(obj)
		ASSERT(item.Func.IsNull() && item.Obj == 0);  // otherwise, protocol conflict

	item.Func = recv;
	item.Obj = obj;
#if defined(PLATFORM_DEBUG_BUILD)
	_PacketState[prefix_char].IsSet = true;
	auto& p = _PacketPrefixChars.push_back();
	p = prefix_char;
#endif

	if(obj)
		_LOGC_VERBOSE("[NET]: Binding Protocol with Header BYTE: '"<<(char)prefix_char<<'\'');
}

void NetworkServiceCore::ResumeDataService()
{
	_DataServiceSuspended = false;
	if(_pDHT)_pDHT->InitiatePeerAnnoucement();
}

void NetworkServiceCore::_Ticking()
{
	os::HighPerformanceCounter	hpc;

	LONGLONG last_hpc = hpc.Get()/1000000LL;
	_Tick = 0;

	while(!_TickingThread.WantExit() && !bWantStop)
	{	
		os::Sleep(50);

		if(_pGNT)
			_NodeDesc.LocalTime32 = _pGNT->GetTimeToReportDword();
		
		LONGLONG h = hpc.Get()/1000000LL;
		if(h - last_hpc >= NET_TICK_UNIT)
		{
			last_hpc = h;

			_UpdateLocalAddress();

			{	// detect external ip changing
				static DWORD _prev_exip_v4 = 0;
				DWORD exip_v4 = GetExternalAddress().IP;

				if(exip_v4 != _prev_exip_v4)
				{
					_prev_exip_v4 = exip_v4;
					if(exip_v4)
						CoreEvent(MODULE_NETWORK, NETWORK_LOCATION_CHANGED);

					if(_pDHT && !_DataServiceSuspended)
						_pDHT->InitiatePeerAnnoucement();
				}
			}

			if(_ConnectionState != NCS_DISCONNECTED)
			{
				if(_pDHT)_pDHT->OnTick(_Tick);
				if(_pLSM)_pLSM->OnTick(_Tick);
				if(_pGNT)_pGNT->OnTick(_Tick);
				if(_pMRC)_pMRC->OnTick(_Tick);
				if(_pAPI)_pAPI->OnTick(_Tick);
            
				for(UINT i=0; i<_OnTickCBCount; i++)
				{
					if(_OnTick[i].Obj && _OnTick[i].Func)
						THISCALL_POLYMORPHISM_INVOKE(OnTick, _OnTick[i].Obj, _OnTick[i].Func, _Tick, GetNetworkTime());
				}
			}
			else
			{
				if((_Tick%15) == 0) // sometime NetworkInterfaces may miss changing event
					_UpdateLocalAddress(true);
			}

			_Tick++;

			if((_Tick%100) == 0)
				CoreEventWith(MODULE_CORE, CORE_TICK, (
					J(tick) = _Tick,
					J(timestamp) = GetNetworkTime()
				));
		}
	}
}

IPv4 NetworkServiceCore::GetExternalAddress() const
{
	if(_pDHT && (_pDHT->IsPublicAddressAvailable() || _NatExternalIP.IsEmpty()))
		return _pDHT->GetPublicAddress();

	return _NatExternalIP;
}

const IPv6&	NetworkServiceCore::GetExternalAddressV6() const
{
	if(_pDHT && (_pDHT->IsPublicAddressAvailableV6() || _NatExternalIPV6.IsEmpty()))
		return _pDHT->GetPublicAddressV6();

	return _NatExternalIPV6;
}

void NetworkServiceCore::_SetConnectionState(NETWORK_CONNECTION_STATE x)
{
	if(x != _ConnectionState)
	{
		_ConnectionState = x;
		CoreEvent(MODULE_NETWORK, NETWORK_CONNECTIVITY_CHANGED);
	}
}

void NetworkServiceCore::_UpdateLocalAddress(bool force_populate)
{
	if(!force_populate)
	{
		auto state = _InterfacesChanging.GetState();
		if(_IsInterfacesReconfiging)
		{
			if(state != inet::NetworkInterfaces::Reconfigured)return;
			_IsInterfacesReconfiging = false;
		}
		else
		{
			if(state == inet::NetworkInterfaces::Reconfiguring)
			{
				_IsInterfacesReconfiging = true;

				if(_pDHT)_pDHT->ResetExternalIP();
				if(_pLSM)_pLSM->ResetExternalPort();
			}

			return;
		}
	}

	inet::InetAddr	addr[NET_LOCAL_ADDRESS_MAXCOUNT];
	DWORD			addr_dword[NET_LOCAL_ADDRESS_MAXCOUNT];
	inet::InetAddr	bc_addr[NET_LOCAL_ADDRESS_MAXCOUNT];
	DWORD			subnet[NET_LOCAL_ADDRESS_MAXCOUNT];
	rt::String		if_name[NET_LOCAL_ADDRESS_MAXCOUNT];
    
	UINT co = inet::GetLocalAddresses(addr, 16, true, bc_addr, subnet
#if defined(PLATFORM_IOS)
        ,"en0,utun,pdp_ip,bridge"  // bind to WIFI,VPN and cellular network
		,if_name
//#elif defined(PLATFORM_MAC)
//        ,"en0,en1"            // bind to Wired Lan, WIFI
//		,if_name
//#elif defined(PLATFORM_LINUX)
//		,"en0,en1"            // bind to Wired Lan
//		,if_name
#endif
    );

	if(co == 0)
	{
		{	THREADSAFEMUTABLE_UPDATE(_LocalNetInterfaces, nics);
			nics.ReadyModify(true);
			nics.Commit();
		}

#if defined(PLATFORM_DEBUG_BUILD)
		THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
		ASSERT(_LocalNetInterfaces.GetImmutable().size() == 0);
#endif

		if(_ConnectionState != NCS_DISCONNECTED)
		{
			_NatMappingState = LNS_NOOP;
			_SetConnectionState(NCS_DISCONNECTED);

			_LOG_ERROR("[NET]: All local interfaces are disconnected.");
		}

		return;
	}

	if(co)
	{
		for(UINT i=0; i<co; i++)
			addr_dword[i] = IPv4().Set(addr[i]).IP;

		THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
		auto& prev = _LocalNetInterfaces.GetImmutable();
		if(prev.size() == co)
		{
			for(UINT i=0; i<co; i++)
				if(prev.find(addr_dword[i]) == prev.end())
					goto ADDRESS_CHANGED;

			ASSERT(prev.size());
			ASSERT(_ConnectionState);
			return; // nothing changed
		}

ADDRESS_CHANGED:
		if(NCS_DISCONNECTED == _ConnectionState)
			if(NETSVC_NAT&_NodeServiceActivated)
				_SetConnectionState(NCS_PRIVATE_NETWORK);
			else
				_SetConnectionState(NCS_PRIVATE_INTRANET);

		int added = 0, removed = 0;

		{	THREADSAFEMUTABLE_UPDATE(_LocalNetInterfaces, nics);
			nics.ReadyModify(true);
			auto& old = nics.GetUnmodified();
			auto& new_map = nics.Get();
		
			for(UINT i=0; i<co; i++)
			{
				auto it = old.find(addr_dword[i]);
				if(it != old.end())
					new_map[it->first] = it->second;
				else
				{	
					auto& n = new_map[addr_dword[i]];
					rt::Zero(n);
					if_name[i].SubStrHead(15).CopyTo(n.InterfaceName);
					n.LocalIP = addr_dword[i];
					n.BroadcastIP = IPv4().Set(bc_addr[i]).IP;
					n.LocalSubnetMask = subnet[i];
					added++;
				}
			}

			removed = added + (int)prev.size() - (int)new_map.size();
			ASSERT(removed >= 0);
		}

		DWORD bc_dword[NET_LOCAL_ADDRESS_MAXCOUNT];
		UINT  bc_count = 0;

		THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
		auto& nic = _LocalNetInterfaces.GetImmutable();
		for(auto& it : nic)
		{
			_LOGC_HIGHLIGHT("[NET]: IPv4 Local NIC: "<<tos(it.second.LocalIP)<<
														'/'<<tos(it.second.LocalSubnetMask)<<
														" Broadcast:"<<tos(it.second.BroadcastIP)<<
														" "<<it.second.InterfaceName
			);

			if(it.second.BroadcastIP && it.second.LocalSubnetMask > 1)
				bc_dword[bc_count++] = it.second.BroadcastIP;
		}

		ASSERT(added || removed);
		
		bool nat_remapping = false;
		if(removed)
		{
			if(_NatInternalIP && !nic.has(_NatInternalIP))
				nat_remapping = true;
		}

		if(added)
		{
			if(_NatInternalIP == 0)nat_remapping = true;
		}

		os::Sleep(100);

		if(nat_remapping || _pDHT && _pDHT->IsPublicAddressAvailable() && _NatExternalIP.IP && !nic.has(_NatInternalIP))
		{	
			nat_remapping = true;
		}

		if(nat_remapping)
		{
			os::Thread* ipv4_thread = _New(os::Thread);
			os::Thread* ipv6_thread = _New(os::Thread);
			{
				EnterCSBlock(_DetermineConnectionThreadsCS);
				_DetermineConnectionThreads.insert(ipv4_thread);
				_DetermineConnectionThreads.insert(ipv6_thread);
			}

			ipv4_thread->Create([this,ipv4_thread](){
							_DetermineConnectionState(ipv4_thread);
							return os::Thread::THREAD_OBJECT_DELETED_ON_RETURN;
						});
			
			ipv6_thread->Create([this,ipv6_thread](){
							_DetermineConnectionStateV6(ipv6_thread);
							return os::Thread::THREAD_OBJECT_DELETED_ON_RETURN;
						});
		}

		if(_pDHT)
			_pDHT->ForceRefresh();

		if(_pLSM)
		{	
			_pLSM->SetBroadcastAddresses(bc_dword, bc_count);
			_pLSM->ForceRefresh();
		}
	}
}

void NetworkServiceCore::_UpdateLocalSwarmBroadcastAddresses()
{
	if(_pLSM)
	{
		DWORD bc_dword[NET_LOCAL_ADDRESS_MAXCOUNT];
		UINT  bc_count = 0;

		THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
		auto& nic = _LocalNetInterfaces.GetImmutable();
		for(auto& it : nic)
		{
			if(it.second.BroadcastIP && it.second.LocalSubnetMask > 1)
				bc_dword[bc_count++] = it.second.BroadcastIP;
		}

		_pLSM->SetBroadcastAddresses(bc_dword, bc_count);
		_pLSM->ForceRefresh();
	}
}

void NetworkServiceCore::_CloseAllSockets()
{
	_Socket.Close();
	_SocketV6.Close();

	if(_pLSM)_pLSM->CloseDiscoverySocket();
}

DWORD NetworkServiceCore::GetLocalIP(DWORD ip_peer) const
{
	THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
	auto& nic = _LocalNetInterfaces.GetImmutable();
	for(auto it : nic)
	{
		if(it.second.IsSameSubnet(ip_peer))
			return it.second.LocalIP;
	}

	if(_NatInternalIP)return _NatInternalIP;

	return nic.size()?nic.begin()->second.LocalIP:0;
}

bool NetworkServiceCore::IsSubnetIP(DWORD ip) const
{
	THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
	auto& nic = _LocalNetInterfaces.GetImmutable();
	for(auto it : nic)
	{
		if(it.second.IsSameSubnet(ip))
			return true;
	}

	return false;
}

void NetworkServiceCore::SetAppNames(const rt::String_Ref& appname, LPCSTR dht_ver, LPCSTR dht_app_tag)
{
	if(!appname.IsEmpty())
	{
		_UPnpAppName = appname;
		LocalSwarm::SetMessageAppName(appname);
	}

	MainlineDHT::SetMessageVersionTags(dht_ver, dht_app_tag);
}

void NetworkServiceCore::_DetermineConnectionStateV6(os::Thread* th)
{
	if(NETSVC_NAT&_NodeServiceActivated)
	{
		UPnpRouter	net_if;
		if(!_UPnpAppName.IsEmpty())
			net_if.SetAppName(_UPnpAppName);

		bool discovered = false;
		for(UINT i=0; i<10; i++)
		{
			if(th->WantExit())goto THREAD_END;
			if((discovered = net_if.Discover(true)))break;

			if(th->WantExit())goto THREAD_END;
			os::Sleep(1000, &th->WantExit());
		}
		
		rt::String ex_ip;
		if(discovered && net_if.GetExternalIP(ex_ip))
		{
			if(th->WantExit())goto THREAD_END;

			inet::InetAddrV6 addr;

			addr.SetAddress(net_if.GetInternalIP());
			memcpy(_NatInternalIPV6, addr.GetBinaryAddress(), 16);

			addr.SetAddress(ex_ip);
			_NatExternalIPV6.Set(addr);
			_NatExternalIPV6.SetPort(_LocalPortV6);  // hack ...

			_LOGC_HIGHLIGHT("[NET]: UPnP Discovered: "<<tos(_NatInternalIPV6)<<" => "<<tos(_NatExternalIPV6.IP));
		}
	}

THREAD_END:
	EnterCSBlock(_DetermineConnectionThreadsCS);
	_DetermineConnectionThreads.erase(th);
}

void NetworkServiceCore::_DetermineConnectionState(os::Thread* th)
{
	if(NETSVC_NAT&_NodeServiceActivated)
	{
		os::Sleep(100);

		UPnpRouter	net_if;
		if(!_UPnpAppName.IsEmpty())
			net_if.SetAppName(_UPnpAppName);

		_NatMappingState = LNS_SOLVING;
		rt::String ex_ip;

		bool discovered = false;
		for(UINT i=0; i<10; i++)
		{
			if(th->WantExit())goto THREAD_END;
			if((discovered = net_if.Discover()))break;

			if(th->WantExit())goto THREAD_END;
			os::Sleep(1000, &th->WantExit());
		}

		if(discovered && net_if.GetExternalIP(ex_ip))
		{
			if(th->WantExit())goto THREAD_END;

			inet::InetAddr addr;

			THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
			auto& nic = _LocalNetInterfaces.GetImmutable();

			addr.SetAddress(net_if.GetInternalIP());
			DWORD ip = IPv4().Set(addr).IP;
			if(nic.has(ip))
			{
				_NatInternalIP = ip;
				addr.SetAddress(ex_ip);
				_NatExternalIP.IP = IPv4().Set(addr).IP;

				_LOGC_HIGHLIGHT("[NET]: UPnP Discovered: "<<tos(_NatInternalIP)<<" => "<<tos(_NatExternalIP.IP));

				_NatExternalIP.SetPort(0);
				_NatMappingState = LNS_MAPPING;

				int target_port = 0;
				if(_pDHT)
				{
					for(UINT i=0; i<5; i++)
						if(_pDHT->IsPublicAddressAvailable())
						{
							IPv4 exip = _pDHT->GetPublicAddress();
							target_port = exip.Port();
							if(nic.has(exip.IP))
								goto HAVE_PUBLIC_IP;

							break;
						}
						else os::Sleep(1000);
				}
			
				if(target_port == 0)
					target_port = (0xffff)&(rand()|1024);

				ASSERT(_LocalPort);
				if(net_if.AddPortMapping(_LocalPort, target_port))
				{
					_NatMappingState = LNS_MAPPED;
					_NatExternalIP.SetPort(target_port);
					_SetConnectionState(NCS_PRIVATE_NETWORK);

					_LOGC_HIGHLIGHT("[NET]: UPnP Mapped: "<<tos(_NatInternalIP)<<':'<<_LocalPort<<" => "<<tos(_NatExternalIP));

					goto THREAD_END;
				}
			}

			_NatMappingState = LNS_UNMAPPED;
			_SetConnectionState(NCS_PRIVATE_INTRANET);
			goto THREAD_END;
		}
		else
		{
			_NatMappingState = LNS_UNMAPPED;
			_SetConnectionState(NCS_PRIVATE_INTRANET);
			rt::Zero(_NatExternalIP);
			_NatInternalIP = 0;
		}
	}

	if(th->WantExit())goto THREAD_END;

	if(_pDHT)
	{
		{	THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
			auto& nic = _LocalNetInterfaces.GetImmutable();

			for(UINT i=0; i<10; i++)
				if(_pDHT->IsPublicAddressAvailable())
				{
					if(nic.has(_pDHT->GetPublicAddress().IP))
						goto HAVE_PUBLIC_IP;
				}
				else os::Sleep(1000);
		}

		goto THREAD_END;
HAVE_PUBLIC_IP:
		_NatMappingState = LNS_UNNECESSARY;
		_SetConnectionState(NCS_PUBLIC_NETWORK);
	}

THREAD_END:
	EnterCSBlock(_DetermineConnectionThreadsCS);
	_DetermineConnectionThreads.erase(th);
}

const DhtAddress& NetworkServiceCore::GetNodeId() const
{
	static const rt::_details::Zeros<sizeof(DhtAddress)> _;
	return _pDHT?_pDHT->GetNodeId():(DhtAddress&)_;
}

bool NetworkServiceCore::_OnExecuteCommand(const os::CommandLine& cmd, rt::String& out)
{
	rt::String_Ref op[10];
	rt::String_Ref(cmd.GetText(0)).Split(op, sizeofArray(op), '.');

	if(op[1] == "report")
	{
		GetNetStateReport(out);
		return true;
	}
	else if(op[1] == "time")
	{
		bool local = !cmd.HasOption("gmt");

		if(cmd.HasOption("ts") || cmd.HasOption("timestamp"))
		{
			out = rt::tos::Number(GetNetworkTime());
		}
		else if(cmd.HasOption("all"))
		{
			os::Timestamp t(GetNetworkTime());
			out = rt::tos::Timestamp<>(t, local) + rt::SS(" (") + t._Timestamp + ')';
			if(_pGNT)
			{	
				out += rt::SS(" D/V=") + _pGNT->GetTimeDrift() + '/' + _pGNT->GetTimeDriftVariance();

				if(!_pGNT->IsStablized())
				{	
					out += rt::SS(", Resolving");
				}
				else
				{	
					if(_pGNT->IsCasting())
					{	out += rt::SS(", Casting S=") + _pGNT->GetStablizationDegree();
					}
				}
			}
		}
		else if(cmd.HasOption("reset"))
		{
			if(_pGNT)_pGNT->Reset();
			_NodeDesc.LocalTime32 = 0;
			out += "Network time is reset, start resolving now";
		}
		else if(cmd.HasOption("genesis"))
		{
			if(_pGNT)_pGNT->Reset(true);
			_NodeDesc.LocalTime32 = 0;
			out += "Network time is reset as genesis, and start casting";
		}
		else if(cmd.HasOption("b") || cmd.HasOption("bootstrap"))
		{
			if(_pGNT && !_pGNT->IsStablized())
			{
				_pGNT->SetBootstrap();
				out += "Network time is in bootstrap mode, requires lesser samples to stablize";
			}
		}
		else
		{
			os::Timestamp t(GetNetworkTime());
			out = rt::tos::Timestamp<>(t, local);
		}

		return true;
	}
	else if(op[1] == "uptime")
	{
		out += rt::SS() + (GetUpTime() + 500)/1000 + rt::SS(" (") + rt::tos::TimeSpan<>(GetUpTime()) + ')';
		return true;
	}
	else if(op[1] == "events")
	{
		CoreEvents::Get().Jsonify(out);
		return true;
	}
	else if(op[1] == "ap")
	{
		NodeAccessPoints nap;
		GetNodeAccessPoints(nap);
		rt::String nap_str;
		nap.ToString(nap_str);
		out += rt::SS("Access Points PUB=") + (int)nap.PublicCount.v4 + '/' + (int)nap.PublicCount.v6 + 
							rt::SS(" LOC=") + (int)nap.LocalCount.v4 + '/' + (int)nap.LocalCount.v6 + 
							rt::SS(" BNC=") + (int)nap.BouncerCount.v4 + '/' + (int)nap.BouncerCount.v6 + '\n' + 
					   nap_str;
		return true;
	}
	else if(op[1] == "invite")
	{
		rt::String_Ref ip_str = cmd.GetText(1);

		if(ip_str.IsEmpty())
		{	out = "Invite peer missing IP address and port";
			return true;
		}

		NetworkAddress ip;
		{
			inet::InetAddr ipv4;
			inet::InetAddrV6 ipv6;
			if(ipv4.SetAddress(ip_str.Begin()))
				ip.IPv4().Set(ipv4);
			else if(ipv6.SetAddress(ip_str.Begin()))
				ip.IPv6().Set(ipv6);
			else
			{	out = rt::SS("Invite peer failed to parse IP address \'") + op[2] + '\'';
				return true;
			}

			if(ip.Port() == 0)
			{
				out = "Invite peer should not have a zero port";
				return true;
			}
		}

		if(cmd.HasOption("lsm"))
		{
			if(!HasLSM())
			{	out = "Local swarm (LSM) is off";
				return true;
			}

			LSM().InvitePeer(ip);
		}
		else
		{
			if(!HasDHT())
			{	out = "Distributed Hash table (DHT) is off";
				return true;
			}

			UINT swarm_id = cmd.GetOptionAs<UINT>("s|swarm", 1);
			bool conn = cmd.HasOption("c|conn");

			if(!DHT().InvitePeer(swarm_id, ip, conn))
				out = rt::SS("Swarm #") + swarm_id + " is not found";
		}

		return true;
	}

	return false;
}

bool NetworkServiceCore::HasSufficientPeers() const
{
	return	(HasDHT() && DHT().IsMature()) || 
			(HasLSM() && LSM().GetPeerCount() > NET_BROADCAST_DEGREE_MIN);
}

bool NetworkServiceCore::Send(Packet& packet, const NetworkAddress& to, const NetworkAddress& relay_peer, PACKET_SENDING_FLAG flag)
{
	if(to.Type() == NADDRT_IPV4)
	{
		packet.PrependWithPOD<BYTE>(NET_FORWARD_PACKET_HEADBYTE_V4);
		packet.AppendPOD(to.IPv4());
	}
	else
	{
		ASSERT(to.Type() == NADDRT_IPV6);
		packet.PrependWithPOD<BYTE>(NET_FORWARD_PACKET_HEADBYTE_V6);
		packet.AppendPOD(to.IPv6());
	}

	return Send(packet, relay_peer, flag);
}

namespace _details
{
template<typename T_SOCKET, typename T_ADDR, typename T_IPvx>
bool _SocketSend(T_SOCKET& socket, LPVOID p_in, UINT len, T_ADDR& a, const NetworkAddress& to_net, const T_IPvx& exip, PACKET_SENDING_FLAG flag)
{
	LPBYTE p = (LPBYTE)p_in;

	if(flag&(PSF_OBFUSCATION_PROBE|PSF_OBFUSCATION))
	{
		bool ret = true;

		if(flag&PSF_OBFUSCATION_PROBE)
			ret = socket.SendTo(p, len, a);

		if(exip.IsEmpty())
		{	// CLOAKING_HEADER       [cloak_header:2B][xor data(len*(len<<10 + len)]
			LPBYTE obsf_head = p-2;
			*(WORD*)obsf_head = (WORD)CLOAKING_HEADER;
			_details::_ObfuscateTransform(len*((len<<10) + len), p, len);
			return socket.SendTo(obsf_head, len+2, a) || ret;
		}
		else
		{	// CLOAKING_HEADER_IPSIG [cloak_header:2B][IP_Sig:4B][xor data(IP_Sig)]
			LPBYTE obsf_head = p-6;
			*(WORD*)obsf_head = (WORD)CLOAKING_HEADER_IPSIG;
			DWORD& ip_sig = *(DWORD*)(obsf_head + 2);
			ip_sig = exip.GetAddressSignature();
			_details::_ObfuscateTransform(ip_sig, p, len);
			return socket.SendTo(obsf_head, len+6, a) || ret;
		}
	}
	else return socket.SendTo(p, len, a);
}
} // namespace _details

bool NetworkServiceCore::_Send(LPVOID p_in, UINT len, const NetworkAddress& to, PACKET_SENDING_FLAG flag)
{
	if(len == 0)return false;

#if defined(PLATFORM_DEBUG_BUILD)
	if(_PacketState[*(BYTE*)p_in].IsSet)
	{
		auto& state = _PacketState[*(BYTE*)p_in];
		os::AtomicAdd(len, &state.TotalSentBytes);
		os::AtomicIncrement(&state.TotalSentPacket);
	}
#endif

	if(!(NETSVC_HOB&_NodeServiceActivated))
		flag &= ~(PSF_OBFUSCATION|PSF_OBFUSCATION_PROBE);

	switch (to.Type())
	{
	case NADDRT_IPV4:
	{
		inet::InetAddr a;
		to.IPv4().Export(a);
		return _details::_SocketSend(_Socket, p_in, len, a, to, GetExternalAddress(), flag);
	}
	case NADDRT_IPV6:
	{
		inet::InetAddrV6 a;
		to.IPv6().Export(a);
		return _details::_SocketSend(_SocketV6, p_in, len, a, to, GetExternalAddressV6(), flag);
	}
	default:
		return false;
	}
}

void NetworkServiceCore::GetState(NetworkState& ns)
{
	GetBasicState(ns);

	if((ns.DHT_Enabled = _pDHT!=nullptr))
	{
		_pDHT->GetState(ns);
	}

	if((ns.LSM_Enabled = _pLSM!=nullptr))
	{
		_pLSM->GetState(ns);
	}

	if((ns.GNT_Enabled = _pGNT!=nullptr))
	{
		_pGNT->GetState(ns);
	}

	ns.NAT_MappingState = _NatMappingState;
}

void NetworkServiceCore::GetBasicState(NetworkStateBasic& ns)
{
	rt::Zero(ns);

	ns.ConnectivityState = _ConnectionState;
	ns.NodeId = GetNodeId();

	if(_pDHT && _pDHT->IsPublicAddressAvailable())
		ns.ExternalIPv4 = _pDHT->GetPublicAddress();
	else if(_pLSM && _pLSM->IsExternalAddressAvailable())
		ns.ExternalIPv4 = _pLSM->GetExternalAddress();
	else
		rt::Zero(ns.ExternalIPv4);

	if(_pDHT)
		ns.DHT_Mature = _pDHT->IsMature();

	if(_pLSM)
		ns.LSM_NonZero = _pLSM->GetPeerCount() != 0;

	if(_pGNT)
		ns.GNT_Working = _pGNT->IsAvailable();
}

void NetworkServiceCore::Awaken()
{
	if(HasLSM())LSM().Awaken();
    if(HasDHT())DHT().Awaken();
	if(HasMRC())MRC().Awaken();
}

namespace _details
{
bool ParseIpString(rt::String_Ref ipstr, NetworkAddress& out, NETADDR_TYPE type = NADDRT_NULL)
{
	SSIZE_T port_pos = ipstr.FindCharacterReverse(':');
	if(port_pos<4)
		return false;

	int port;
	ipstr.SubStr(port_pos + 1).ToNumber(port);
	if(port<=0 || port > 0xffff) return false;

	if(ipstr[0] == '[' && type != NADDRT_IPV4) // ipv6
	{
		if(ipstr[port_pos - 1] != ']')return false;
		inet::InetAddrV6 addr;
		if(inet_pton(AF_INET6, ALLOCA_C_STRING(rt::String_Ref(ipstr.Begin()+1, &ipstr[port_pos - 1])), &addr.sin6_addr))
		{
			addr.SetPort(port);
			if(!addr.IsValidDestination())
				return false;
			out.IPv6().Set(addr);
		}
		else return false;
	}
	else if(type != NADDRT_IPV6)
	{
		inet::InetAddr addr;
		if(inet_pton(AF_INET, ALLOCA_C_STRING(rt::String_Ref(ipstr.Begin(), &ipstr[port_pos])), &addr.sin_addr))
		{
			addr.SetPort(port);
			if(!addr.IsValidDestination())
				return false;
			out.IPv4().Set(addr);
		}
		else return false;
	}
	return true;
}

bool LoadNetworkAddressTable(LPCSTR fn, rt::BufferEx<NetworkAddress>& out, NETADDR_TYPE type)
{
	rt::String file;
	if(!os::File::LoadText(fn, file))return false;

	rt::String_Ref line;
	while(file.GetNextLine(line))
	{
		if(line.GetLength() <= 6)continue;
		NetworkAddress addr;
		if(!ParseIpString(line, addr, type)) continue;
		
		// dedup
		if(out.Find(addr) == -1 && !addr.IsEmpty())
			out.push_back() = addr;
	}
	return true;
}

bool LoadSwarmNetworkAddressTable(LPCSTR fn, ext::fast_map<NetworkAddress, NetworkAddress>& out, uint32_t max_size)
{
	rt::String file;
	if(!os::File::LoadText(fn, file))return false;

	rt::String_Ref line;
	while(file.GetNextLine(line))
	{
		if(line.GetLength() <= 6)continue;
		rt::String_Ref seg[2];
		if(line.Split(seg, 2, ',') == 0)
			continue;

		NetworkAddress addr, alt;
		if(!ParseIpString(seg[0], addr)) continue;
		ParseIpString(seg[1], alt);
		// dedup
		if(out.has(addr) || addr.IsEmpty()) continue;
		out.insert(std::make_pair(addr, alt));
		if(max_size !=0 && out.size() >= max_size) break;
	}
	return true;
}

bool SaveNetworkAddressTable(LPCSTR fn, const rt::BufferEx<NetworkAddress>& in)
{
	static const rt::SS LN("\r\n");
	rt::String out;
	for(auto& it : in)
	{
		if(it.Type() == NADDRT_IPV4)
		{
			out += tos(it.IPv4()) + LN;
		}
		else if(it.Type() == NADDRT_IPV6)
		{
			out += tos(it.IPv6()) + LN;
		}
	}

	return os::File::SaveText(fn, out, false);
}

bool SaveSwarmNetworkAddressTable(LPCSTR fn, const ext::fast_map<NetworkAddress, NetworkAddress>& in)
{
	static const rt::SS LN("\r\n");
	rt::String out;
	for(auto& it : in)
	{
		if(it.first.Type() == NADDRT_IPV4)
		{
			out += tos(it.first.IPv4());
		}
		else if(it.first.Type() == NADDRT_IPV6)
		{
			out += tos(it.first.IPv6());
		}
		
		if(it.second.IsEmpty())
		{
			out += LN;
			continue;
		}
		
		out += ',';
		if(it.second.Type() == NADDRT_IPV4)
		{
			out += tos(it.second.IPv4()) + LN;
		}
		else if(it.second.Type() == NADDRT_IPV6)
		{
			out += tos(it.second.IPv6()) + LN;
		}
	}

	return os::File::SaveText(fn, out, false);
}

struct nap_item
{				// 0
	int type;	// item_xxxxx
	int weight;
	union {
	IPv4	ipv4;
	IPv6	ipv6;
	NodeAccessPoints::Bouncer_IPv4	bncv4;
	NodeAccessPoints::Bouncer_IPv6	bncv6;
	};
	nap_item(){}
	template<typename T>
	nap_item(int t, int w, const T& c){ type = t; weight = w; rt::Copy((T&)ipv4, c); }
	bool operator < (const nap_item& x) const
	{
		return weight < x.weight;
	}
};
} // namespace _details

bool NetworkServiceCore::GetNodeAccessPoints(NodeAccessPoints& out, UINT size_limit, UINT swarm)
{
	static const int count_max = NodeAccessPoints::COUNT_MAX;

	rt::Zero(out);
	if(size_limit <= offsetof(NodeAccessPoints, AddressData))return false;

	enum {
		item_local_ip4		 = (sizeof(IPv4)<<8)|0,
		item_public_ip4		 = (sizeof(IPv4)<<8)|1,
		item_bouncer_ip4_to4 = (sizeof(NodeAccessPoints::Bouncer_IPv4)<<8)|2,
		item_bouncer_ip4_to6 = (sizeof(NodeAccessPoints::Bouncer_IPv4)<<8)|4,
		item_local_ip6		 = (sizeof(IPv6)<<8)|0|0x10,
		item_public_ip6		 = (sizeof(IPv6)<<8)|1|0x10,
		item_bouncer_ip6_to4 = (sizeof(NodeAccessPoints::Bouncer_IPv6)<<8)|2|0x10,
		item_bouncer_ip6_to6 = (sizeof(NodeAccessPoints::Bouncer_IPv6)<<8)|4|0x10,
	};
					 
	rt::BufferEx<_details::nap_item>	all_items;
	rt::TopWeightedValues<IPv4, count_max>	top_exipv4;
	rt::TopWeightedValues<IPv6, count_max>	top_exipv6;

	int count_exipv4 = 0, count_exipv6 = 0;

	static int wei_ipv6_add = 3100;
	static int wei_bouncer_mul = 1100;
	static int wei_ip_mul = 1000;
	static int wei_altip_add = 10000;

	if(HasDHT())
	{
		if(DHT().IsPublicAddressAvailable())
			top_exipv4.Sample(DHT().GetPublicAddress());

		if(DHT().IsPublicAddressAvailableV6())
			top_exipv6.Sample(DHT().GetPublicAddressV6());

		auto* sw = DHT().GetSwarm(swarm);
		if(sw)
		{
			rt::BufferEx<NetworkAddress>	bouncer;
			rt::BufferEx<NetworkAddress>	bouncer_altip;
			rt::BufferEx<NetworkAddress>	exip;

			sw->CopyPeersAsBouncers(bouncer, bouncer_altip, exip);

			for(auto& ip: exip)
			{
				if(ip.IsIPv4()){ top_exipv4.Sample(ip.IPv4()); }
				else{ top_exipv6.Sample(ip.IPv6()); ASSERT(ip.IsIPv6()); }
			}

			count_exipv4 = top_exipv4.GetUniqueValueCount();
			count_exipv6 = top_exipv6.GetUniqueValueCount();

			int exip_bnc_count_v4[count_max];
			int exip_bnc_count_v6[count_max];
			rt::Zero(exip_bnc_count_v4);
			rt::Zero(exip_bnc_count_v6);

			for(int i=0; i<count_exipv4; i++)
				all_items.push_back() = { item_public_ip4, i*wei_ip_mul, top_exipv4.Get(i) };

			for(int i=0; i<count_exipv6; i++)
				all_items.push_back() = { item_public_ip6, i*wei_ip_mul + wei_ipv6_add, top_exipv6.Get(i) };

			for(int i=0; i<bouncer.GetSize(); i++)
			{
				if(bouncer[i].IsIPv4())
				{
					int idx = top_exipv4.FindValue(exip[i].IPv4());
					ASSERT(idx>=0);
					int wei = exip_bnc_count_v4[idx]*wei_bouncer_mul + 1 + idx*wei_ip_mul;
					exip_bnc_count_v4[idx]++;

					NodeAccessPoints::Bouncer_IPv4 bnc = { bouncer[i].IPv4(), (BYTE)idx };
					all_items.push_back() = { item_bouncer_ip4_to4, wei, bnc };

					if(bouncer_altip[i].IsIPv6())
					{
						NodeAccessPoints::Bouncer_IPv6 bnc = { bouncer_altip[i].IPv6(), (BYTE)idx };
						all_items.push_back() = { item_bouncer_ip6_to4, wei + wei_altip_add, bnc };
					}
				}
				else
				{
					int idx = top_exipv6.FindValue(exip[i].IPv6());
					ASSERT(idx>=0);

					int wei = exip_bnc_count_v6[idx]*wei_bouncer_mul + 1 + idx*wei_ip_mul + wei_ipv6_add;
					exip_bnc_count_v6[idx]++;

					NodeAccessPoints::Bouncer_IPv6 bnc = { bouncer[i].IPv6(), (BYTE)(0x80|idx) };
					all_items.push_back() = { item_bouncer_ip6_to6, wei, bnc };

					if(bouncer_altip[i].IsIPv4())
					{
						NodeAccessPoints::Bouncer_IPv4 bnc = { bouncer_altip[i].IPv4(), (BYTE)(0x80|idx) };
						all_items.push_back() = { item_bouncer_ip4_to6, wei + wei_altip_add, bnc };
					}
				}
			}
		}
	}

	// local ips
	if(GetLocalPort())
	{	// v4
		THREADSAFEMUTABLE_SCOPE(_LocalNetInterfaces);
		auto& ips = _LocalNetInterfaces.GetImmutable();
		int co = rt::min((UINT)NodeAccessPoints::COUNT_MAX, (UINT)ips.size());
		auto it = ips.begin();
		for(int i=0; i<co; i++, it++)
		{
			IPv4 ip;
			ip.IP = it->second.LocalIP;
			ip.SetPort(_LocalPort);

			all_items.push_back() = { item_local_ip4, i*wei_ip_mul + 10, ip };
		}
	}

	if(GetLocalPortV6())
	{	
		int collected = 0;
		rt::BufferEx<inet::NetworkInterface>	nic;
		if(inet::NetworkInterfaces::Populate(nic, true, true))
		{
			auto* localv6 = (IPv6*)out.GetLocalIPv6();
			for(auto& ni : nic)
			{
				if(ni.HasIPv6())
				{
					for(int i=0; i<(int)ni.v6Count; i++)
					{
						IPv6 ip;
						ip.Set(ni.v6, GetLocalPortV6());

						all_items.push_back() = { item_local_ip6, collected*wei_ip_mul + 10 + wei_ipv6_add, ip };
						collected++;
						if(collected == NodeAccessPoints::COUNT_MAX)goto LOCAL_V6_COLLECTED;
					}
				}
			}
		}
LOCAL_V6_COLLECTED:
		while(false);
	}

	all_items.Sort();
	UINT size = offsetof(NodeAccessPoints, AddressData);
	int count_max_out = 0;
	for(UINT i=0; i<all_items.GetSize(); i++)
	{
		auto& x = all_items[i];
		if(size + (x.type>>8) > size_limit || count_max_out == count_max)
		{	all_items.ShrinkSize(i+1);
			break;
		}
		size += (x.type>>8);

		switch(x.type)
		{
		case item_local_ip4:		out.LocalCount.v4++;	count_max_out = rt::max(count_max_out, (int)out.LocalCount.v4); break;
		case item_public_ip4:		out.PublicCount.v4++;	count_max_out = rt::max(count_max_out, (int)out.PublicCount.v4); break;
		case item_bouncer_ip4_to4:	
		case item_bouncer_ip4_to6:	out.BouncerCount.v4++;	count_max_out = rt::max(count_max_out, (int)out.BouncerCount.v4); break;
		case item_local_ip6:		out.LocalCount.v6++;	count_max_out = rt::max(count_max_out, (int)out.LocalCount.v6); break;
		case item_public_ip6:		out.PublicCount.v6++;	count_max_out = rt::max(count_max_out, (int)out.PublicCount.v6); break;
		case item_bouncer_ip6_to4:	
		case item_bouncer_ip6_to6:	out.BouncerCount.v6++;	count_max_out = rt::max(count_max_out, (int)out.BouncerCount.v6); break;
		default: ASSERT(0);
		}
	}

	auto* local_ipv4 = rt::_CastToNonconst(out.GetLocalIPv4());
	auto* local_ipv6 = rt::_CastToNonconst(out.GetLocalIPv6());
	auto* public_ipv4 = rt::_CastToNonconst(out.GetPublicIPv4());
	auto* public_ipv6 = rt::_CastToNonconst(out.GetPublicIPv6());
	auto* bouncer_ipv4 = rt::_CastToNonconst(out.GetBouncerIPv4());
	auto* bouncer_ipv6 = rt::_CastToNonconst(out.GetBouncerIPv6());

	for(auto& x : all_items)
	{
		switch(x.type)
		{
		case item_local_ip4:		*local_ipv4++ = x.ipv4;		break;
		case item_public_ip4:		*public_ipv4++ = x.ipv4;	break;
		case item_local_ip6:		*local_ipv6++ = x.ipv6;		break;
		case item_public_ip6:		*public_ipv6++ = x.ipv6;	break;
		case item_bouncer_ip4_to6:	
		case item_bouncer_ip4_to4:	*bouncer_ipv4++ = x.bncv4;	break;
		case item_bouncer_ip6_to6:	
		case item_bouncer_ip6_to4:	*bouncer_ipv6++ = x.bncv6;	break;
		default: ASSERT(0);
		}
	}

	ASSERT(out.GetSize() == size);

	return true;
}

void NodeAccessPoints::ToString(rt::String& out) const
{
	static const rt::SS tab("    ");
	out += rt::SS("Public IPs:\n");

	{	auto* ip = GetPublicIPv4();
		for(UINT i=0; i<PublicCount.v4; i++)
			out += tab + tos(ip[i]) + '\n';
	}
	{	auto* ip = GetPublicIPv6();
		for(UINT i=0; i<PublicCount.v6; i++)
			out += tab + tos(ip[i]) + '\n';
	}

	out += rt::SS("Local IPs:\n");
	{	auto* ip = GetLocalIPv4();
		for(UINT i=0; i<LocalCount.v4; i++)
			out += tab + tos(ip[i]) + '\n';
	}
	{	auto* ip = GetLocalIPv6();
		for(UINT i=0; i<LocalCount.v6; i++)
			out += tab + tos(ip[i]) + '\n';
	}

	if(BouncerCount.Total())
	{
		out += rt::SS("Bouncers:\n");
		{	auto* bnc = GetBouncerIPv4();
			for(UINT i=0; i<BouncerCount.v4; i++)
				out += tab + tos(bnc[i].Ip) + " => " + 
					   (bnc[i].IsDestinationIPv6()?
						   tos(GetBouncerDestinationIPv6(bnc[i].DestinationIndex)):
						   tos(GetBouncerDestinationIPv4(bnc[i].DestinationIndex))
					   ) + '\n';
		}
		{	auto* bnc = GetBouncerIPv6();
			for(UINT i=0; i<BouncerCount.v6; i++)
				out += tab + tos(bnc[i].Ip) + " => " + 
					   (bnc[i].IsDestinationIPv6()?
						   tos(GetBouncerDestinationIPv6(bnc[i].DestinationIndex)):
						   tos(GetBouncerDestinationIPv4(bnc[i].DestinationIndex))
					   ) + '\n';
		}
	}
}

void NetworkServiceCore::NatHolePunch(const IPv4& ip)
{
	PacketBuf<500> buf;
	rt::Randomizer(time(nullptr)).Randomize(buf.Claim(100), 100);
	buf.Commit(100);

	NetworkAddress to(ip);
	Send(buf, to);
}

} // namespace upw
