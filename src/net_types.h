#pragma once
#include "net_policy.h"
#include "../externs/miniposix/core/inet/inet.h"
#include "../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "./dht/dht_base.h"

#ifndef PLATFORM_64BIT
#error 64-bit Platform is required.
#endif

namespace upw
{

static const UINT NETWORK_ADDRESS_SIZE =	2 + 16;

enum CORE_NOTIFICATION_ID
{
	MODULE_CORE		= 0,
	MODULE_NETWORK	= 1,

	CORE_TICK			= 0,
	CORE_EXIT			= 1,
	CORE_CRITICAL_HALT	= 2,

	NETWORK_CONNECTIVITY_CHANGED = 0,
	NETWORK_ADDRESS_CHANGED,
	NETWORK_LOCAL_SWARM_CHANGED,
	NETWORK_SWARM_CHANGED,		// param = swarm_id tos(DhtAddress)
	NETWORK_LOCATION_CHANGED,	// param = ipv4 (DWORD)
	NETWORK_TIME_STABLIZED,
	NETWORK_MULTILINK_BUSY,
	NETWORK_MULTILINK_IDLE,
	NETWORK_GDP_PRIORITY_BUSY,
	NETWORK_GDP_PRIORITY_IDLE,
};

#pragma pack(push,1)
struct IPv4		// dht compact binary representation of the requestor's IP and port
{
	TYPETRAITS_DECLARE_POD;
	DWORD		IP;
protected:
	WORD		PortNS;
public:
	WORD		Port() const { return htons(PortNS); }
	void		SetPort(WORD port){ PortNS = htons(port); }
	bool		IsEmpty() const { return IP == 0 || PortNS == 0; }
	void		Empty(){ rt::Zero(*this); }

	void		Set(LPCVOID ip, int port){ IP = *((DWORD*)ip); PortNS = htons(port); }
	auto&		Set(const inet::InetAddr& inetaddr){ IP = *((DWORD*)inetaddr.GetBinaryAddress()); PortNS = *(WORD*)inetaddr.GetBinaryPort(); return *this; }
	void		Export(inet::InetAddr& inetaddr) const { inetaddr.SetBinaryAddress(&IP); inetaddr.SetBinaryPort(&PortNS); }
	DWORD		GetAddressSignature() const { return IP^(PortNS*PortNS); }

	bool		operator == (const IPv4& b) const { return IP == b.IP && PortNS == b.PortNS; }
	bool		operator != (const IPv4& b) const { return IP != b.IP || PortNS != b.PortNS; }
    //auto&		operator = (const IPv4& b){ IP = b.IP; PortNS = b.PortNS; return b; }
};

struct IPv6		// dht compact binary representation of the requestor's IP and port 
{
	TYPETRAITS_DECLARE_POD;
	BYTE		IP[16];
protected:
	WORD		PortNS;
	void		_AssignIP(LPCVOID ip){ ((ULONGLONG*)IP)[0] = ((ULONGLONG*)ip)[0]; ((ULONGLONG*)IP)[1] = ((ULONGLONG*)ip)[1]; }
public:
	void		Empty(){ rt::Zero(*this); }
	bool		IsEmpty() const { return PortNS == 0 || (((ULONGLONG*)IP)[0] == 0 && ((ULONGLONG*)IP)[1] == 0); }
	WORD		Port() const { return htons(PortNS); }
	void		SetPort(WORD port){ PortNS = htons(port); }
	void		Set(LPCVOID ip, unsigned short port){ _AssignIP(ip); PortNS = htons(port); }
	auto&		Set(const inet::InetAddrV6& na){ _AssignIP(na.GetBinaryAddress()); PortNS = *(WORD*)na.GetBinaryPort(); return *this; }
	void		Export(inet::InetAddrV6& inetaddr) const { inetaddr.SetBinaryAddress(IP); inetaddr.SetBinaryPort(&PortNS); }
	DWORD		GetAddressSignature() const { return (*(DWORD*)IP)^(*(DWORD*)(IP+4))^(*(DWORD*)(IP+8))^(*(DWORD*)(IP+12))^(PortNS*PortNS); }

	bool		IsTrivial() const { return 0ULL == *(ULONGLONG*)IP; }

	bool		operator == (const IPv6& b) const { return ((ULONGLONG*)IP)[0] == ((ULONGLONG*)b.IP)[0] && ((ULONGLONG*)IP)[1] == ((ULONGLONG*)b.IP)[1] && PortNS == b.PortNS; }
	bool		operator != (const IPv6& b) const { return ((ULONGLONG*)IP)[0] != ((ULONGLONG*)b.IP)[0] || ((ULONGLONG*)IP)[1] != ((ULONGLONG*)b.IP)[1] || PortNS != b.PortNS; }
    //auto&		operator = (const IPv6& b){ ((ULONGLONG*)IP)[0] = ((ULONGLONG*)b.IP)[0]; ((ULONGLONG*)IP)[1] = ((ULONGLONG*)b.IP)[1]; PortNS = b.PortNS; return b; }

	static const IPv6& Zero(){ static const rt::_details::Zeros<sizeof(IPv6)> zero_na; return (const IPv6&)zero_na; }
};

struct CloakedIPv4
{	
	TYPETRAITS_DECLARE_POD;
	IPv4		IP;
	BYTE		padding[2];
	const IPv4& operator = (const IPv4& ip){ IP = ip; rt::Zero(padding); return ip; }
};

struct CloakedIPv6
{	
	TYPETRAITS_DECLARE_POD;
	IPv6		IP;
	BYTE		padding[6];
	const IPv6& operator = (const IPv6& ip){ IP = ip; rt::Zero(padding); return ip; }
};

#pragma pack(pop)

enum NETADDR_TYPE
{
	NADDRT_NULL = 0,
	NADDRT_VOID = 0x80,
	NADDRT_IPV4 = sizeof(IPv4),
	NADDRT_IPV6 = sizeof(IPv6),
};

#pragma pack(push,1)
struct NetworkAddress
{
	TYPETRAITS_DECLARE_NON_POD;
public:
	WORD			_Type;	// NETADDR_TYPE
	union {
	BYTE			_AddrData[NETWORK_ADDRESS_SIZE];
	IPv4	_IP4;
	IPv6	_IP6;
	};

	struct hash_compare
	{	// traits class for hash container
		enum // parameters for hash table
		{	bucket_size = 4,	// 0 < bucket_size
			min_buckets = 8		// min_buckets = 2 ^^ N, 0 < N
		};
		size_t	operator()(const NetworkAddress& key) const { return rt::_details::_HashValue(&key, key.GetLength()); }
		bool	operator()(const NetworkAddress& _Keyval1, const NetworkAddress& _Keyval2) const {	return memcmp(&_Keyval1,&_Keyval2,_Keyval2.GetLength()) < 0; }
	};
	NetworkAddress(const NetworkAddress& x){ rt::CopyByteTo(x, *this); }
	NetworkAddress(const IPv4& x){ _Type = NADDRT_IPV4; _IP4 = x; }
	NetworkAddress(const IPv6& x){ _Type = NADDRT_IPV6; _IP6 = x; }
	NetworkAddress(ext::HASHKEY_CTOR_TYPE x = ext::CTOR_ZERO)
	{	if(x == ext::CTOR_ZERO)_Type = NADDRT_NULL; 
		else if(x == ext::CTOR_VOID)_Type = NADDRT_VOID;
		else ASSERT(0);
	}

	void				Empty(){ _Type = NADDRT_NULL; }
	UINT				GetLength() const { return sizeof(_Type) + AddressLength(); }
	
	// Destination Address
	bool				IsIPv4() const { return Type() == NADDRT_IPV4; }
	bool				IsIPv6() const { return Type() == NADDRT_IPV6; }
	IPv4&				IPv4(){ if(IsEmpty()){_Type = NADDRT_IPV4;} ASSERT(Type() == NADDRT_IPV4); return _IP4; }
	IPv6&				IPv6(){ if(IsEmpty()){_Type = NADDRT_IPV6;} ASSERT(Type() == NADDRT_IPV6); return _IP6; }
	const auto&			IPv4() const { ASSERT(IsIPv4()); return _IP4; }
	const auto&			IPv6() const { ASSERT(IsIPv6()); return _IP6; }

	bool				IsEmpty() const { return _Type == NADDRT_NULL || _Type == NADDRT_VOID; }
	ULONGLONG			GetAddressSignature() const { ASSERT(!IsEmpty()); return _Type == NADDRT_IPV6?IPv6().GetAddressSignature():IPv4().GetAddressSignature(); }

	NETADDR_TYPE		Type() const { return (NETADDR_TYPE)_Type; }
	LPCBYTE				Address() const { return _AddrData; }
	UINT				AddressLength() const 
						{	ASSERT(Type() == NADDRT_NULL || Type() == NADDRT_IPV4 || Type() == NADDRT_IPV6);
							return Type();
						}
	UINT				Port() const 
						{	if(_Type == NADDRT_IPV4){ return _IP4.Port(); }
							if(_Type == NADDRT_IPV6){ return _IP6.Port(); }
							return 0;
						}
	void				SetPort(UINT port)
						{	if(_Type == NADDRT_IPV4){ _IP4.SetPort(port); return; }
							if(_Type == NADDRT_IPV6){ _IP6.SetPort(port); return; }
							ASSERT(0);
						}
	bool operator ==	(const NetworkAddress& b) const 
						{	if(_Type != b._Type)return false;
							return b.IsEmpty()?true : memcmp(this, &b, GetLength()) == 0;
						}
	bool operator !=	(const NetworkAddress& b) const
						{	if(_Type != b._Type)return true;
							return b.IsEmpty()?false : memcmp(this, &b, GetLength()) != 0;
						}
    auto& operator =	(const NetworkAddress& b){ rt::Copy(*this, b); return b; }
    auto& operator =	(const ::upw::IPv4& b){ _Type = NADDRT_IPV4; _IP4 = b; return b; }
    auto& operator =	(const ::upw::IPv6& b){ _Type = NADDRT_IPV6; _IP6 = b; return b; }
};

struct NetTimestamp
{
	static const int64_t Max = 0xffffffffffffULL;

	DWORD	Low;
	WORD	High;

	NetTimestamp() = default;
	NetTimestamp(const NetTimestamp&) = default;
	NetTimestamp(int64_t x){ ASSERT(x>=0); *this = x; }
	operator	int64_t() const { return (int64_t)((Max&*(uint64_t*)this)<<NET_TIMESTAMP_UNIT_SHIFT); }
	void		operator = (int64_t x){ ASSERT(x>=0); x>>=NET_TIMESTAMP_UNIT_SHIFT; Low = (DWORD)x; High = *(((LPCWORD)&x)+2); }
	int			compare_with(const NetTimestamp& x) const
				{	int c = (int)High - (int)x.High;
					if(c)return c;
					if(Low < x.Low)return -1;
					if(Low > x.Low)return 1;
					return 0;
				}

	TYPETRAITS_DECLARE_POD;
};

#pragma pack(pop)

enum PACKET_SENDING_FLAG: DWORD
{
	//TBD:  the actual behave is not implemented
	PSF_NORMAL = 0,		// retry async sending until succeded, or sync sending
	PSF_DROPABLE,		// try async sending once, and message is dropped if not success
	PSF_PRESISTENT,		// try async sending once, and message is cached if not success, will be retry async sending later
	PSF_FORWARD_ONLY,	// SwarmBroadcast::Broadcast will send to only forward peers
	PSF_SENDING_BEHAVE_MASK = 0xf,

	// followings are bitwise defined
	// sending flag
	PSF_SKIP_LOCALSWARM		= 0x100,
	PSF_OBFUSCATION			= 0x200,
	PSF_OBFUSCATION_PROBE	= 0x400,
	// recv flag
	PSF_IP_RESTRICTED_VERIFIED = 0x1000
};

struct PacketRecvContext
{
	NetworkAddress			RecvFrom;
	NetworkAddress*			pRelayPeer;
	PACKET_SENDING_FLAG		SendingFlag; // PSF_IP_RESTRICTED_ENC, PSF_OBFUSCATION

	PacketRecvContext(const NetworkAddress& from, PACKET_SENDING_FLAG flag):RecvFrom(from){ pRelayPeer = nullptr; SendingFlag = flag; }
	PacketRecvContext(){ pRelayPeer = nullptr; SendingFlag = PSF_NORMAL; }
};

#pragma pack(push,1)
struct SwarmState
{
	UINT		NodesReachable;
	UINT		NodesTotal;
	UINT		Latency;		//msec
	UINT		LatencyMax;
};

struct Peer
{
	NetworkAddress	NetAddress;
	DhtAddress		DhtAddress;
};
#pragma pack(pop)

struct NetworkStateBasic
{
	DWORD		ConnectivityState;
	IPv4		ExternalIPv4;
	bool		DHT_Mature;
	bool		LSM_NonZero;
	bool		GNT_Working;
	DhtAddress	NodeId;
};

struct NetworkState_LSM
{
	UINT		LSM_PeerCount;
	UINT		LSM_SubnetPeerCount;
	UINT		LSM_Latency;		//msec
	UINT		LSM_LatencyMax;
};

struct NetworkState_DHT
{
	IPv4		DHT_PublicIPv4;
	IPv6		DHT_PublicIPv6;

	UINT		DHT_Latency;
	ULONGLONG	DHT_SpaceSize;
	ULONGLONG	DHT_ReachableSpaceSize;
	UINT		DHT_DistanceBase;
	SwarmState	DHT_Buckets[DHT_SPACE_SIZE - DHT_BUCKET_DISTANCE_BASE];

	UINT		DHT_NodeNew;
	UINT		DHT_NodeLongterm;
	UINT		DHT_NodeZombie;

	ULONGLONG	DHT_InboundDataSize;
	ULONGLONG	DHT_OutbounDatadSize;
	UINT		DHT_InboundPacketNum;
	UINT		DHT_OutboundPacketNum;

	ULONGLONG	DHT_PingSent;
	ULONGLONG	DHT_FindNodeSent;
	ULONGLONG	DHT_GetPeerSent;
	ULONGLONG	DHT_AnnouncePeerSent;

	ULONGLONG	DHT_PingReplyed;
	ULONGLONG	DHT_FindNodeReplyed;
	ULONGLONG	DHT_GetPeerReplyed;
	ULONGLONG	DHT_AnnouncePeerReplyed;

	ULONGLONG	DHT_RecvPing;
	ULONGLONG	DHT_RecvFindNode;
	ULONGLONG	DHT_RecvGetPeer;
	ULONGLONG	DHT_RecvAnnouncePeer;
	ULONGLONG	DHT_RecvError;
	ULONGLONG	DHT_RecvDroppedPacket;
	ULONGLONG	DHT_RecvCorruptedPacket;
};

struct NetworkState_GNT
{
	LONGLONG	GNT_NetworkTime;
	LONGLONG	GNT_LocalClockDrift;
	bool		GNT_Available;
	bool		GNT_Stablized;
	bool		GNT_Casting;
};

struct NetworkState: public NetworkStateBasic,
					 public NetworkState_DHT,
					 public NetworkState_LSM,
					 public NetworkState_GNT
{
	bool		DHT_Enabled;
	bool		LSM_Enabled;
	bool		GNT_Enabled;

	bool		NAT_Enabled;
	DWORD		NAT_MappingState;
};

struct PeerList	// DHT Peers
{
	UINT			BackwardCount;
	UINT			ForwardCount;
	NetworkAddress	Peers[1];  // [Backward Peers][Forward Peers]

	auto*			BackwardPeers() const { return Peers; }
	auto*			BackwardPeers(){ return Peers; }
	auto*			ForwardPeers() const { return Peers + BackwardCount; }
	auto*			ForwardPeers(){ return Peers + BackwardCount; }
	UINT			TotalCount() const { return BackwardCount + ForwardCount; }
};

struct LocalPeerList // LSM Peers
{
	UINT			Count;
	UINT			Reserved;
	NetworkAddress	Peers[1]; // Capacity = Reserved
};

#pragma pack(push, 1)
struct NodeAccessPoints
{
	struct IpCount
	{	BYTE v4:4;
		BYTE v6:4;
		UINT GetIpDataSize() const { return v4*sizeof(IPv4) + v6*sizeof(IPv6); }
		UINT Total() const { return v4 + v6; }
	};

	struct Bouncer_IPv4
	{
		IPv4	Ip;
		BYTE	DestinationIndex;	// refer to Public Ip list
		bool	operator == (const IPv4& ip) const { return Ip == ip; }
		bool	IsDestinationIPv6() const { return DestinationIndex&0x80; }
	};

	struct Bouncer_IPv6
	{
		IPv6	Ip;
		BYTE	DestinationIndex;	// refer to Public Ip list
		bool	operator == (const IPv6& ip) const { return Ip == ip; }
		bool	IsDestinationIPv6() const { return DestinationIndex&0x80; }
	};

	TYPETRAITS_DECLARE_NON_POD;
	static const UINT COUNT_MAX = 8;
	static const UINT AddressDataSizeMax = COUNT_MAX*(2*sizeof(IPv4) + 2*sizeof(IPv6) + sizeof(Bouncer_IPv4) + sizeof(Bouncer_IPv6));

	IpCount		PublicCount;
	IpCount		LocalCount;
	IpCount		BouncerCount;
	BYTE		AddressData[AddressDataSizeMax];	// [{PublicIPv4}][{PublicIPv6}][{LocalIPv4}][{LocalIPv6}][{Bouncerv4}][{Bouncerv6}]
	
	const IPv4*	GetPublicIPv4() const { return (IPv4*)AddressData; }
	const IPv6*	GetPublicIPv6() const { return (IPv6*)&AddressData[sizeof(IPv4)*PublicCount.v4]; }
	const IPv4*	GetLocalIPv4() const { return (IPv4*)&AddressData[PublicCount.GetIpDataSize()]; }
	const IPv6*	GetLocalIPv6() const { return (IPv6*)&AddressData[PublicCount.GetIpDataSize() + sizeof(IPv4)*LocalCount.v4]; }
	auto*		GetBouncerIPv4() const { return (const Bouncer_IPv4*)&AddressData[PublicCount.GetIpDataSize() + LocalCount.GetIpDataSize()]; }
	auto*		GetBouncerIPv6() const { return (const Bouncer_IPv6*)&AddressData[PublicCount.GetIpDataSize() + LocalCount.GetIpDataSize() + sizeof(Bouncer_IPv4)*BouncerCount.v4]; }
	auto&		GetBouncerDestinationIPv4(BYTE dest_index) const { ASSERT(dest_index<0x80); return GetPublicIPv4()[dest_index&0xf]; }
	auto&		GetBouncerDestinationIPv6(BYTE dest_index) const { ASSERT(dest_index&0x80); return GetPublicIPv6()[dest_index&0xf]; }

	void		DropBouncers(){ ((BYTE&)BouncerCount) = 0; }
	UINT		GetSize() const { return offsetof(NodeAccessPoints, AddressData) + 
									 PublicCount.GetIpDataSize() + LocalCount.GetIpDataSize() + 
									 sizeof(Bouncer_IPv4)*BouncerCount.v4 + sizeof(Bouncer_IPv6)*BouncerCount.v6;
								}
	void		ToString(rt::String& out) const;
};
#pragma pack(pop)

struct tos: public ::rt::tos::S_<1, 128>
{	
	tos() = default;

	void _set(LPCSTR str){ _set(rt::String_Ref(str)); }
	template<typename T>
	void _set(T&& str)
	{	_len = str.CopyTo(_p);
		ASSERT(_len < 128);
		_p[_len] = 0;
	}

	tos(const NetworkAddress& n)
	{	switch(n.Type())
		{	case NADDRT_NULL:	_set("[nullptr]");			break;
			case NADDRT_IPV4:	new (this) tos(n.IPv4());	break;
			case NADDRT_IPV6:	new (this) tos(n.IPv6());	break;
			default: ASSERT(0);
		}
	}
	tos(const DhtAddress& n){ new (this) rt::tos::Binary<128, false>(n); }
	tos(const IPv4& x)
	{	LPCBYTE addr = (LPCBYTE)&x.IP;
		_set(rt::tos::Number(addr[0]) + '.' + rt::tos::Number(addr[1]) + '.' + rt::tos::Number(addr[2]) + '.' + rt::tos::Number(addr[3]) + ':' + x.Port());
	}
	tos(DWORD ipv4)
	{	BYTE* d = (BYTE*)&ipv4;
		_set(rt::tos::Number(d[0]) + '.' + rt::tos::Number(d[1]) + '.' + rt::tos::Number(d[2]) + '.' + rt::tos::Number(d[3]));
	}
	tos(const IPv6& x):tos(x.IP)
	{	rt::_details::string_ops::itoa(x.Port(), _p + _len + 1);
		_p[_len] = ':';
		_len += strlen(_p + _len + 1) + 1;
	}
	tos(const BYTE ipv6[16])
	{	inet::InetAddrV6 addr;
		addr.SetBinaryAddress(ipv6);
		addr.GetDottedDecimalAddress(_p+1);
		_len = strlen(_p+1) + 2;
		_p[0] = '[';
		_p[_len-1] = ']';
	}
};

} // namespace upw

STRINGIFY_ENUM_BEGIN(PACKET_SENDING_FLAG, upw)
	STRINGIFY_ENUM(PSF_NORMAL)
	STRINGIFY_ENUM(PSF_DROPABLE)
	STRINGIFY_ENUM(PSF_PRESISTENT)
	STRINGIFY_ENUM(PSF_SKIP_LOCALSWARM)
	STRINGIFY_ENUM(PSF_OBFUSCATION)
	STRINGIFY_ENUM(PSF_OBFUSCATION_PROBE)
STRINGIFY_ENUM_END(PACKET_SENDING_FLAG, upw)

namespace std
{

template<>
struct hash<::upw::IPv4>: public rt::_details::hash_compare_fix<::upw::IPv4> {};

template<>
struct hash<::upw::IPv6>: public rt::_details::hash_compare_fix<::upw::IPv6> {};

template<>
struct hash<::upw::NetworkAddress>: public ::upw::NetworkAddress::hash_compare {};

}
