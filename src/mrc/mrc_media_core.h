#pragma once
#include "../../externs/miniposix/core/os/thread_primitive.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../stg/storage_interface.h"
#include "../gdp/gdp_base.h"


namespace upw
{
class GossipDataPropagation;

enum MrcMediaPriority : uint8_t
{
	MMP_USER_REQUESTED	= 100,	// data will be presented immediately to the user and is the current focus of the user
	MMP_UI_AWAITING		= 90,	// data will be presented immediately to the user but may-or-may-not be the current focus of the user
	MMP_PREFETCH		= 77,	// data will not be presented right now, but will be in the near future
	MMP_USER_DATA		= 50,	// data will possibly be presented, but not now
	MMP_ANONYMOUS_DATA	= 30,	// data will never be presented, but is sync-ed to support others
	MMP_RETRY			= 10	// anything requested but failed, and retry
};

class MrcMediaRelayCore // Hash => <MaxExpiration, BlobData>, size of BlobData < 16MB, working for all swarms
{
	NetworkServiceCore*		_pNet;
	GossipDataPropagation*	_pGDP;
	MessageRelayCore&		_Node;
	uint32_t				_DefaultSwarmId; // when DhtAddress.IsZero()

public:
#pragma pack(push, 1)
	struct BlobMetadata
	{
		uint8_t				Mime;
		NetTimestamp		Expire;
	};
#pragma pack(pop)

protected:
	class DataRelayCBS
	{
	protected:
		struct LoadRecord
		{
			GdpAsyncDataFetch	Async;
			LoadRecord*			pNext;
			explicit LoadRecord(const GdpAsyncDataFetch* async_cb);
		};

		rt::hash_map<GdpHash, LoadRecord*> _Map;
	
	public:
		void Append(const GdpHash& key, const GdpAsyncDataFetch* async_cb);
		void Invoke(const GdpHash& key, const GdpData* data);
		void CancelAll(GossipDataPropagation* gdp);
	};

	os::CriticalSection		_CoreCS;
	DataRelayCBS			_CBS;

	KVStore					_TimeHashIndex;		// <Time,Hash> => void, Sort by Time_HashValue
	KVStore					_Offloads;			// Hash => Offloaded
	KVStore					_LocalBlobs;		// Hash => Blob
	KVStore					_KeySwarmMap;		// Hash => DhtAddress[]
	KVStore					_Blobs;				// Hash => Blob
	ext::fast_set<GdpHash>	_MissedHash;		// cached non-existing Key

	MrcMediaWorkload		_Workload;
	bool					_Suspended;
	bool					_bInit;

	void				_Thrink();
	void				_RemoveOffload(MrcMediaOffloadItem& offload);

	uint32_t			_GetSwarmIds(const GdpHash& hash, rt::BufferEx<UINT>& swarm_ids);
	void				_Retrieve(const GdpHash* hash, uint8_t priority);
	void				_Set(const GdpHash& h, const void* data, uint32_t size);

	bool				_LoadAsync(const GdpHash& hash, rt::BufferEx<BYTE>& buf_dst, const GdpAsyncDataFetch* async_cb, uint8_t priority);
	bool				_Load(const GdpHash& key, std::string& out, const GdpAsyncDataFetch* async_cb, uint8_t priority);
	void				_Save(const GdpHash& h, const void* data, uint32_t size);

	void				_CalcWorkload();
	void				_UpdateDataSwarmInfo(const GdpHash& hash, const DhtAddress* swarms, uint32_t swarm_count);

	GdpDataMemLayout	_GdsDataDiscovered(const GdpHash& hash, const GdpHint& hint, LPCBYTE sample, UINT sample_len, UINT data_len);
	bool				_GdsDataRecvUnfragmented(const GdpHash& hash, const GdpHint& hint, LPBYTE data, UINT data_len);
	bool				_GdsDataRecvAssembled(GdpDataInMem* data, const GdpHint& hint);
	GdpDataPage*		_GdsDataRequest(const GdpHash& hash, const GdpHint& hint, UINT page_no);

public:
	MrcMediaRelayCore(MessageRelayCore& node);
	~MrcMediaRelayCore(){ Term(); }
	
	bool				Init(UINT default_swarm_id, const MrcMediaRelayStorage& storage, bool bInitSuspended = false);
	void				Term();
	void				OnTick(UINT tick);

	bool				Save(uint8_t mime, const GdpData& data, MrcMediaOffloadItem& out, const DhtAddress* swarms, uint32_t swarm_count);
	bool				LoadMediaOffloaded(const GdpHash& encrypted_data_hash, MrcMediaOffloadItem& offload);
	GdpData				Load(const GdpHash& hash, const GdpAsyncDataFetch* async_cb, uint8_t priority);
	bool				Load(const GdpHash& hash, rt::BufferEx<BYTE>& out){ return _LoadAsync(hash, out, nullptr, MMP_USER_REQUESTED); }
	int					GetAvailability(const GdpHash& hash); // [0, 1000], -1 for non-existed
	bool				Export(const GdpHash& hash, const char* dest, rt::String* opt_final_path = nullptr);
	
	bool				RetainExistingOffload(const GdpHash& hash, uint32_t ttl_days, MrcMediaOffloadItem& out); // for media forwarding
	bool				MediaOffloadDiscovered(const MrcMediaOffload& entry, const GdpHash* secret, const DhtAddress* swarm_addr); // return false if data is invalid, e.g. pow not fulfilled
	void				GetWorkload(rt::String& out);
	MrcMediaWorkload	GetWorkload();

	bool				CheckOffloadPow(MrcMediaOffloadItem& offload);
	bool				CheckOffloadPow(MrcMediaOffload& offload);
	bool				CheckOffloadPow(const MrcMediaOffload& offload);

	void				Suspend() { _Suspended = true; }
	bool				IsSuspend() const { return _Suspended; }
	void				Resume() { _Suspended = false; }


	void				CancelPendingLoads(bool clear_gds = false);
	void				CleanUnusefulData(os::ProgressReport& prog);
};

} // namespace upw
