#pragma once
#include "net_types.h"
#include "./dht/dht_base.h"

namespace ext
{
class RocksStorage;
}

namespace upw
{

typedef ext::RocksStorage	ServiceStorage;

enum NETWORK_SERVICE_TAG
{
	NETSVC_GNT				= (1<<0),
	NETSVC_DHT				= (1<<1),
	NETSVC_LSM				= (1<<2),
	NETSVC_MRC				= (1<<3),
	NETSVC_GDP				= (1<<4),
	NETSVC_PBC				= (1<<5),
	NETSVC_HOB				= (1<<6),
	NETSVC_MLT				= (1<<7),
	NETSVC_DVS				= (1<<8),

	NETSVC_MASK_REPORTING	= 0x0fff,

	// non-reporting
	NETSVC_NAT				= (0x1000<<0),
	NETSVC_CONSOLE			= (0x1000<<1),
	NETSVC_API				= (0x1000<<2),
	NETSVC_SMB				= (0x1000<<3),
	NETSVC_MASK_NONLOCAL	= NETSVC_GNT|NETSVC_DHT|NETSVC_LSM|NETSVC_GDP|NETSVC_PBC|NETSVC_HOB|NETSVC_NAT,

	// flag
	NETSVC_GNT_GENESIS		= 0x10000,
	NETSVC_DATA_SERVICE_SUSPENDED = 0x20000,
};

enum NETWORK_CONNECTION_STATE
{
	NCS_DISCONNECTED = 0,
	NCS_PRIVATE_NETWORK,
	NCS_PRIVATE_INTRANET,
	NCS_PUBLIC_NETWORK
};

enum NAT_MAPPING_MODE
{
	LNS_NOOP = 0,		// not ready
	LNS_SOLVING,		// solving external ip
	LNS_MAPPING,		// mapping in-progress
	LNS_MAPPED,
	LNS_UNMAPPED,		// Mapping is required but unable to do that
	LNS_UNNECESSARY		// Nat Mapping is not required
};

#pragma pack(push,1)
struct NetworkPeerDesc
{	
	static const uint32_t NodeNameSizeMax = 6;
	union {
	struct {
		WORD		ServicesActivated;		// reporting ones
		char		NodeName[NodeNameSizeMax];
	};	LONGLONG	_padding;
	};
	NetworkPeerDesc(){ _padding = 0; }
	bool	IsEmpty(){ return _padding == 0; }

	bool	HasDHT() const { return ServicesActivated&NETSVC_DHT; }
	bool	HasGNT() const { return ServicesActivated&NETSVC_GNT; }
	bool	HasLSM() const { return ServicesActivated&NETSVC_LSM; }
	bool	HasGDP() const { return ServicesActivated&NETSVC_GDP; }
	bool	HasHOB() const { return ServicesActivated&NETSVC_HOB; }
	bool	HasPBC() const { return ServicesActivated&NETSVC_PBC; }
	bool	HasMLT() const { return ServicesActivated&NETSVC_MLT; }
	bool	HasMRC() const { return ServicesActivated&NETSVC_MRC; }

	rt::String_Ref	GetNodeName() const { return rt::String_Ref(NodeName, NodeName+NodeNameSizeMax).GetLengthRecalculated(); }
	void			SetNodeName(const rt::String_Ref& x)
					{	uint32_t sz = (uint32_t)x.SubStr(0, NodeNameSizeMax).CopyTo(NodeName);
						rt::Zero(NodeName + sz, NodeNameSizeMax - sz);
					}
};

struct NetworkNodeDesc: public NetworkPeerDesc
{
	volatile DWORD		LocalTime32;			// low 32-bit of the network time (unix time in msec)
	NetworkNodeDesc(){ LocalTime32 = 0; }
};
#pragma pack(pop)


/////////////////////////////////////////////////////////////////////////////////
// Notification Sink for CoreEvents
struct CoreEventSink
{
	virtual void OnCoreEventNotify(DWORD module_id, DWORD msg_id, LPCSTR json, UINT json_size) = 0;
};

/////////////////////////////////////////////////////////////////////////////////
// Local Async API Handlers
class LocalApiResponder;
struct AsyncApiHandler
{
	virtual bool OnApiInvoke(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp) = 0;
};

class Packet
{
	template<UINT length, UINT prefix_reserved>
	friend class PacketBuf;
	friend class SwarmBroadcast;
	friend class NetworkServiceCore;

	UINT	_InitOffset;
protected:
#if defined(PLATFORM_DEBUG_BUILD)
	bool	_DataRuined;
#endif
	UINT	_SizeMax;
	UINT	_Offset;
	UINT	_Length;
	char	_Data[1];

	LPSTR	_BufBase(){ return _Data + _Offset; }

public:
	Packet(UINT len, UINT prefix_reserved)
	{	_SizeMax=len+prefix_reserved; _InitOffset=_Offset=prefix_reserved; _Length = 0;
#if defined(PLATFORM_DEBUG_BUILD)
		_DataRuined = false; 
#endif
	}

	LPCSTR	GetData() const { return _Data + _Offset; }
	LPSTR	GetData(){ return _Data + _Offset; }
	UINT	GetLength() const { return _Length; }
	UINT	Remain() const { return _SizeMax - _Offset - _Length; }

	// append data
	LPSTR	Claim(UINT len = 0){ return (_Offset + _Length + len <= _SizeMax)?_BufBase() + _Length:nullptr; }
	void	Commit(UINT len){ ASSERT(_Offset + _Length + len <= _SizeMax); _Length += len; }
	template<typename T>
	void	Commit(){ Commit(sizeof(T)); }

	template<typename StrExp>
	void	Append(const StrExp& str){ Commit((UINT)str.CopyTo(Claim())); }
	void	Append(LPCSTR str){ Append(rt::String_Ref(str)); }
	void	Append(LPCVOID p, UINT len){ memcpy(Claim(len), p, len); Commit(len); }
	template<typename T>
	void	AppendPOD(const T& d){ Append(&d, sizeof(T)); }
	template<typename T>
	auto&	AppendPOD(){ LPSTR ret = Claim(sizeof(T)); Commit(sizeof(T)); return *(T*)ret; }

	template<typename StrExp>
	auto&	operator << (const StrExp& str){ Append(str); return *this; }

protected:
	// prepend, only used in low-level protocol handlers: SwarmBroadcast
	LPSTR	PrependWith(UINT len = 0){ ASSERT(_Offset>=len); _Offset-=len; _Length+=len; return _BufBase(); }
	template<typename T>
	T&		PrependWithPOD(){ return *(T*)PrependWith(sizeof(T)); }
	template<typename T>
	void	PrependWithPOD(const T& x){ *(T*)PrependWith(sizeof(T)) = x; }

	template<typename StrExp>
	void	Prepend(const StrExp& str){ str.CopyTo(PrependWith((UINT)str.GetLength())); }
	void	Prepend(LPCSTR str){ Prepend(rt::String_Ref(str)); }
	void	Prepend(LPCVOID p, UINT len){ memcpy(PrependWith(len), p, len); }
	void	PrependReset(){ _Offset = _InitOffset; }
};

template<UINT length = 2048 - NET_PACKET_PREFIX_DEFAULT_SIZE, UINT prefix_reserved = NET_PACKET_PREFIX_DEFAULT_SIZE>
class PacketBuf: public Packet
{
	friend class NetworkServiceCore;

public:
	static const UINT PREFIX_RESERVED = (prefix_reserved + 7)&0xfffffff8;
	static const UINT SIZE = (length + 7)&0xfffffff8;

protected:
	char	_Buffer[SIZE + PREFIX_RESERVED - (sizeof(Packet) - offsetof(Packet, _Data))];

public:
	PacketBuf():Packet(SIZE, PREFIX_RESERVED){}
	PacketBuf(LPCSTR str):Packet(SIZE + PREFIX_RESERVED, PREFIX_RESERVED){ _Length = rt::String_Ref(str).CopyTo(_BufBase()); }
	template<typename StrExp>
	PacketBuf(const StrExp& str):Packet(SIZE + PREFIX_RESERVED, PREFIX_RESERVED){ _Length = (UINT)str.CopyTo(_BufBase()); }

	template<typename StrExp>
	auto&	operator << (const StrExp& str){ Append(str); return *this; }
	void	Reset(){ _Length = 0; PrependReset(); }
};


template<typename POD, UINT prefix_reserved = NET_PACKET_PREFIX_DEFAULT_SIZE>
struct PacketPOD: public PacketBuf<sizeof(POD), prefix_reserved>
{	
	typedef PacketBuf<sizeof(POD), prefix_reserved> _SC;
private:
	void	Reset();
	LPSTR	Claim(UINT len);
	void	Commit(UINT len);
	template<typename StrExp>
	void	Append(const StrExp& str);
	void	Append(LPCSTR str);
	void	Append(LPCVOID p, UINT len);

	template<typename StrExp>
	auto&	operator << (const StrExp& str);

	LPSTR	_PodBase(){ return &_SC::_Data[_SC::PREFIX_RESERVED]; }
public:
	template<typename P>
	PacketPOD(P x){ _SC::_Length = sizeof(POD); new (_PodBase()) POD(x); }
	PacketPOD(){ _SC::_Length = sizeof(POD); new (_PodBase()) POD(); }

	void			SetLength(UINT size){ ASSERT(size<=sizeof(POD)); _SC::_Length = size; }
	POD*			operator -> (){ return (POD*)_PodBase(); }
	const POD*		operator -> () const { return (const POD*)_PodBase(); }
	operator		POD&(){ return *(POD*)_PodBase(); }
	operator const	POD&() const { return *(POD*)_PodBase(); }
	//void			SetPacketLength(UINT s){ _SC::_Used = s; }
};

} // namespace upw

