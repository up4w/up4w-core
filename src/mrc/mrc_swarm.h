#pragma once
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../stg/storage_interface.h"
#include "mrc_base.h"


namespace upw
{
namespace _details
{
struct MrcFragmentAssembler;

#pragma pack(push, 1)
struct MrcFragmentedHeader
{
	BYTE				Magic;		// MUST BE MRC_PROTOCOL_CHAR_EXT_SWARM, "Y"
	MrcContactPointNum	CP_ID;

	/* include whole MRC_PACKET
	BYTE		MAGIC;
	BYTE		OpCode;	
	BYTE		Data[...]
	 */
};
#pragma pack(pop)

} // namespace _details

class Packet;
class NetworkServiceCore;
struct MrcMessage;
struct MrcEnvelope;

#pragma pack(push, 1)
struct MrcDagStatus
{
	BYTE		Flag;
	BYTE		Count;
	MrcMsgHash	Heads[1];

	bool		IsValid(int status_size)
				{	return  ( status_size >= offsetof(MrcDagStatus, Heads) )
						&&	( Count <= MRC_STATUS_PING_MAX_COUNT )
						&&  ( status_size == offsetof(MrcDagStatus, Heads) + Count * sizeof(MrcMsgHash) 
					);
				}
};
#pragma pack(pop)

using Void_Func_With_MrcMessage = std::function<void(const MrcMessage& msg)>;

class MrcMessageRelayStore	// use rocksdb as storage, keep latest in memory for 1 hour, save & load in 24 hours
{
	friend class MrcMessageRelaySwarm;

	struct MissingRecord
	{
		int64_t			ReferTime = 0;
		int64_t			RequestLastTime = 0;
		int64_t			RequestCount = 0;
		MissingRecord(int64_t pt, int64_t rt): ReferTime(pt), RequestLastTime(rt){}
		MissingRecord() {}
	};

	struct TimeDAGHashKey
	{
		TYPETRAITS_DECLARE_POD;
		rt::BigEndianNumber<int64_t, false>		Time;
		MrcMsgHash								Hash;
	};

	os::CriticalSection							_StoreCS;
	rt::hash_map <MrcMsgHash, MrcMessage*>		_DAGPackets;	// MrcMsgHash -> MrcMessage*
	std::multimap<int64_t, MrcMsgHash>			_DAGTimeHashIndex; // Timestamp --> MrcMsgHash

	rt::hash_map <MrcMsgHash, MissingRecord>	_MissingMap;	// missing-MrcMsgHash -> request_record
	rt::hash_set <MrcMsgHash>					_LostSet;		// lost-MrcMsgHash, timeout & missing
	rt::hash_set <MrcMsgHash>					_Referred;		// referred-MrcMsgHash
	rt::hash_set <MrcMsgHash>					_UnReferred;	// unreferred-MrcMsgHash
	rt::hash_set <MrcMsgHash>					_UnconfirmedSet;// unreferred-MrcMsgHash, which send by self

	std::function<void(MrcMsgHash hash)> _Func_Callback_Missing = nullptr; //  callback when find missing in local
	
	bool				_bCacheDBResult = false;	// if true, every query will be cached
	KVStore				_Packets;					// MrcMsgHash -> MrcMessage
	KVStore				_TimeHashIndex;				// index of TimeDAGHashKey

	volatile bool		_Opened = false;
	volatile bool		_StopSearch = true;
	volatile int64_t	_SearchCount = 0;

	void				_PutInMem(MrcMsgHash hash, MrcMessage* packet);
	bool				_Has(MrcMsgHash hash);

	struct MrcRuntimeStatus
	{
		volatile int64_t	MEM_StoreFrom = 0;
		volatile int64_t	DB_StoreFrom = 0;
		volatile int64_t	NOW = 0;
		volatile int64_t	TIME_Acceptable = 0;

		volatile int64_t	MRC_COUNT = 0;
		volatile int64_t	MRC_UNREFERRED = 0;
		volatile int64_t	MRC_MISSING = 0;
	};
	MrcRuntimeStatus	_Status;

public:
	enum PacketSource {
		PKSRC_DATABASE = 0,
		PKSRC_LOCALHOST,
		PKSRC_NETWORK,
	};

	MrcMessageRelayStore(std::function<void(MrcMsgHash hash)>func_callback_missing);

	bool				Init(const MrcMessageRelayStorage& store); // nullptr means legacy mode, use default name
	void				Term();

	//void				Search(osn_messages* messages, std::function<void(const MrcMessage& packet)> callback);
	void				StopSearch();
	void				Search(int64_t from, int64_t to, const ext::fast_set<MrcContactPointNum>* cps_ptr, std::function<void(const MrcMessage& packet)> callback);
	void				SearchMissing(std::function<void(MrcMsgHash hash)> callback);
	void				SearchMissing(const MrcDagStatus& remote_status, std::function<void(MrcMsgHash hash)> callback);
	void				SearchUnconfirmed(std::function<void(const MrcMessage& packet)> callback);

	int					PickParents(MrcMsgHash hash[MRC_PACKETS_PARENT_COUNT]);

	void				Thrink();
	void				Dump(rt::String out, bool show_detail = false);
	
	MrcWorkload			GetWorkload();
	int64_t				GetMissingTime(int64_t from); // return the lastest missing 
	void				GetPooled(Void_Func_With_MrcMessage cb, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit);

	const MrcDagStatus*	BuildStatus(rt::BufferEx<BYTE>& buf); // result -> buf, free not required (hash list of all unreferred messages)
	const MrcMessage*	Get(MrcMsgHash hash, bool cache_in_mem); // result -> thread_local buf, free not required
	MrcMessage*			Put(MrcMsgHash hash, const MrcMessage& packet, PacketSource source); // result is a new clone, managed by caller, free required
};


class MrcMessageRelaySwarm
{
	MrcMessageRelayStore			_Store;
	bool							_bExtended = false;
	_details::MrcFragmentAssembler*	_Fragments;

	NetworkServiceCore*				_pNetCore = nullptr;
	DhtAddress*						_pSwarmAddress = nullptr;
	UINT							_SwarmId = 0;
	
	std::function<bool(const MrcMessage* data, MrcRecvContext& ctx)> _OnMessageCallback;

protected:
	volatile int64_t	_RecvLocalTime = 0;
	volatile int64_t	_RecvMsgLocalTime = 0;
	inline void			_UpdateRecvLocalTime() { _RecvLocalTime = os::Timestamp::Get(); }
	inline void			_UpdateRecvMsgLocalTime() { _RecvMsgLocalTime = os::Timestamp::Get(); }

	UINT				_uint_mask[32];
	UINT				_status_i = 0;
	UINT				_status_v;
	UINT				_status_g = 0;
	rt::Randomizer		_status_r;
	UINT				_tick_count = 0;

	void	_Request(MrcMsgHash hash, const NetworkAddress* dest=nullptr);
	int		_SendPacket(const MrcMessage& packet, const NetworkAddress* dest);
	void	_SendStatus(bool initiative, const MrcDagStatus& status, const NetworkAddress* dest = nullptr);

	void	_UpdateStoreTime();

	void	_OnRecvFromDB(const MrcMessage& packet, MrcRecvContext::SourceType source);

protected:
	
	void	_ReponseStatus(const MrcDagStatus& remote_status, const NetworkAddress& peer_addr);

	void	_AppenLayeredHeader(const Packet& src, Packet& dst);
	bool	_Send(Packet& packet, const NetworkAddress& to, PACKET_SENDING_FLAG flag = PSF_NORMAL);
	int		_Broadcast(Packet& packet, const NetworkAddress* skip = nullptr, PACKET_SENDING_FLAG flag = PSF_NORMAL);
	bool	_NetCore_Send(Packet& packet, const NetworkAddress& to, PACKET_SENDING_FLAG flag);
	int		_NetCore_Broadcast(Packet& packet, const NetworkAddress* skip, PACKET_SENDING_FLAG flag);
	UINT	_NetGetActiveDegree() const;

public:
	int64_t				ActiveTime = 0;
	DhtAddress			SwarmAddress = { 0 };
	static const int	CP_ID_COUNT = 5;
	MrcContactPointNum	CP_ID_Array[CP_ID_COUNT] = { MrcContactPointZero };

	MrcMessageRelaySwarm(NetworkServiceCore* net, std::function<bool(const MrcMessage* data, MrcRecvContext& ctx)> func_callback_recvdata);
	~MrcMessageRelaySwarm();
	bool			Init(UINT swarm_id, StorageFactory* store, bool default_swarm);			// legacy mode
	void			Term();
	void			Replay(int64_t from, int64_t to, MrcRecvContext::SourceType source);
	void			Replay(int64_t from, int64_t to, const ext::fast_set<MrcContactPointNum>& cps, MrcRecvContext::SourceType source);
	void			StopReplay();
	//void			Replay(osn_messages* messages, MrcRecvContext::SourceType source);
	int				Broadcast(const MrcMessage& packet, const NetworkAddress* skip = nullptr);
	MrcMsgHash		BroadcastEnvelope(const MrcEnvelope& envelope, int64_t ttl_sec, bool directly_recv_by_self = true); // return msg crc
	void			Sync() { rt::BufferEx<BYTE> buf; auto* status = _Store.BuildStatus(buf); if(status) _SendStatus(true, *status); }
	int64_t			GetMissingTime(int64_t from);
	int64_t			GetLastRecvLocalTime() { return _RecvLocalTime; }
	int64_t			GetLastRecvMsgLocalTime() { return _RecvMsgLocalTime; }
	void			GetWorkload(rt::String& out);
	MrcWorkload		GetWorkload();
	void			GetPooled(Void_Func_With_MrcMessage cb, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit);


	void			OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx, bool pure);	// call by MessageRelayCore for receiving data
	void			OnTick(UINT tick);														// call by MessageRelayCore for driving task
	bool			OnCommand(const os::CommandLine& cmd, rt::String& out);					// call by MessageRelayCore for command prompt
};

} // namespace upw
