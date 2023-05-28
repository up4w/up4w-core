#pragma once

#include <atomic> 
#include "../netsvc_types.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"
#include "../secure_identity.h"

//#define NETWORK_LOST_PACKET

#define GDP_DEFAULT_SWARM_SIZE			32
#define GDP_BLOB_MAXSIZE				(128*1024*1024)
#define GDP_BLOB_PAGESIZE				(256*1024)
#define GDP_MTU_SIZE					NET_PACKET_SIZEMAX
#define GDP_BLOB_NONPAGED_MAXSIZE		GDP_MTU_SIZE
#define GDP_PACKET_FRAGMENT_SIZE		1024

#define GDP_TASK_MAX_IDLE				(10*1000) // delete download task if no data received within GDP_TASK_MAX_IDLE ms
#define GDP_DATAPAGE_MEMORY_LIMIT		(256U*1024*1024)
#define GDP_DATAPAGE_GC_INTERVAL		(10*1000)
#define GDP_PROBE_TASK_INTERVAL			(3*1000)
#define GDP_PROBE_TASK_TIMEOUT			(10*1000)
#define GDP_BROADCAST_TASK_TIMEOUT		(30*1000)
#define GDP_EXIT_TIMEOUT				(1*1000)

#ifdef NET_GDP_HINT_SIZE
#define GDP_HINT_SIZE					NET_GDP_HINT_SIZE
#else
#define GDP_HINT_SIZE					4
#endif

#define GDP_AUTO_PUSH_COUNT				16

#define	GDP_TASK_MAX_PEERS				32
#define	GDP_TASK_MAX_REQUESTS			1024
#define	GDP_PACKET_MAX_KEYS				32
#define	GDP_PACKET_MAX_RANGES			128

#define GDP_BIN_TO_BASE16(T) (rt::tos::Base16OnStack<>(T))
#define GDP_BIN_TO_BASE32(T) (rt::tos::Base32CrockfordFavCharLowercaseOnStack<>(T))

#define GDP_MALLOC(N)	_Malloc8AL(BYTE, N)
#define GDP_MEMSET(PTR, VAL, SIZE) memset(PTR, VAL, SIZE)
#define GDP_MEMCPY(DST, SRC, SIZE) memcpy(DST, SRC, SIZE)
#define GDP_MEMCMP(BUF1, BUF2, SIZE) memcmp(BUF1, BUF2, SIZE)
#define GDP_FREE(PTR) _SafeFree8AL(PTR)


namespace upw
{
#pragma pack(push, 1)

enum GdpLogStatus
{
	GLS_OFF		= 0,
	GLS_ON		= 1,

	GLS_LOG		= 1,
	GLS_TRACE	= 2,
};

extern GdpLogStatus _GDP_LOG_STATUS_;
extern UINT	_GDP_LOSS_RATE_;

#if defined(PLATFORM_RELEASE_BUILD) || defined(PLATFORM_SUPPRESS_DEBUG_LOG)
#define GDP_LOG(X) ((void)0)
#define GDP_TRACE(X) ((void)0)
#else
#define GDP_LOG(X) if(_GDP_LOG_STATUS_ >= GLS_LOG) _LOGC(os::TickCount::Get() <<" [GDP] " << X)
#define GDP_TRACE(X) if(_GDP_LOG_STATUS_ >= GLS_TRACE) _LOGC(os::TickCount::Get() <<" [GDP] " << X)
#endif

struct GdpDownloadTaskStatus
{
	UINT DataLen;
	UINT Downloaded;
};

typedef HashValue GdpHash;

struct GdpHint
{
	BYTE	Module:3;
	BYTE	Reserved0:5;
	BYTE	Reserved1[GDP_HINT_SIZE-1];

	GdpHint(){};
	GdpHint(DWORD h){ *(DWORD*)this = h; }
};

static_assert(sizeof(GdpHint) == GDP_HINT_SIZE);

struct GdpKey
{
	GdpHash Hash = { 0 };
	GdpHint Hint = { 0 };

	GdpKey() {}
	GdpKey(const GdpHash& hash, const GdpHint& hint) : Hash(hash), Hint(hint) {}
	bool operator == (const GdpKey& B) const { return GDP_MEMCMP(&this->Hash, &B.Hash, sizeof(GdpKey)) == 0; }
};

struct GdpRange
{
	UINT	Offset;
	UINT	Length;
};

enum GdpOptionsFlags
{
	GDPOPT_CUSTOMIZED_KEY		= 0x01,	// the key is not native hash value of the payload, thus hash verification will be skipped after the data is fully received
	GDPOPT_PAYLOAD_MTU_SIZED	= 0x02,	// the data most likily smaller than an MTU size (NET_PACKET_SIZEMAX)
	GDPOPT_PAYLOAD_PAGE_SIZED	= 0x04,	// the data most likily smaller than an page size (GDP_BLOB_PAGESIZE)
	GDPOPT_NO_EXPIRATION		= 0x08, // keep trying to download until delete it
};

struct GdpOptions
{
	UINT	DataSizeMax;		// maximum possible size of the data, any data violate the size restrict will be discarded 
	UINT	DataSizeMin;		// minimum size of the data, any data violate the size restrict will be discarded
	BYTE	Priority;			// greater value means higher priority
	BYTE	Flag;				// bit defined in GdpOptionsFlags
};

struct GdpDataInMem
{
	typedef struct{
		GdpHash Hash;
		UINT	DataLen;
	} PrefixHeader;

	union {
		PrefixHeader	Header;
		BYTE			Mem[sizeof(PrefixHeader)];
		struct {
			//BYTE Prefix[PrefixSize];		PrefixSize from high 32-bits of OnDataDiscovered(), include: PrefixHeader + some bytes
			//BYTE Data[Prefix.DataLen];	
			//BYTE Suffix[SuffixSize];		SuffixSize from low 32-bits of OnDataDiscovered()
		} Layout;
	};

};

struct GdpDataInMemHelper
{
private:
	bool Initialized = false;

	LPBYTE pGDIM = nullptr;
	LPBYTE pData = nullptr;

public:
	~GdpDataInMemHelper();

	bool				Initialize(const GdpHash& hash, INT type, UINT prefix_size, UINT data_len, UINT suffix_size);
	bool				GetInitialized() { return Initialized; }

	GdpDataInMem*		GetDataInMem() { return (GdpDataInMem*)pGDIM; }
	GdpHash*			GetHash() { return (GdpHash*)pGDIM; }
	UINT				GetDataLen() { return ((GdpDataInMem::PrefixHeader*)pGDIM)->DataLen; }
	LPBYTE				GetData() { return pData; }

	GdpDataInMem*		Detach() { assert(Initialized); Initialized = false; return (GdpDataInMem*)pGDIM; }
};

struct GdpPieceRecord
{
	GdpHash*	Hash;
	GdpHint		Hint;

	UINT		DataTotalSize;

	UINT		Offset;
	WORD		Length;

	LPBYTE		Data;
	WORD		DataLen;
};
#pragma pack(pop)


struct GdpTaskInfo
{
	GdpKey		Key;
	GdpOptions Options;
	UINT		Swarm_Id = 0xFFFFFFFF;

	UINT		Create_TS = 0;
	UINT		Probe_TS = 0;
	

	bool		IsCustomizedKey() { return Options.Flag & GDPOPT_CUSTOMIZED_KEY; }
	bool		IsNoExpiration() { return Options.Flag & GDPOPT_NO_EXPIRATION; }
	void		RefreshProbe() { Probe_TS = os::TickCount::Get(); };
	bool		ProbeElapsed(UINT ms) { return os::TickCount::Get() - Probe_TS > ms; }
	bool		CreateElapsed(UINT ms) { return os::TickCount::Get() - Create_TS > ms; }
	bool		IsValidSize(UINT n) { return n >= Options.DataSizeMin && (Options.DataSizeMax == 0 || n <= Options.DataSizeMax); }

	GdpTaskInfo();
	~GdpTaskInfo();
};

using TaskInfoPtr = std::shared_ptr<GdpTaskInfo>;
using Key_TaskInfoPtr_Map = rt::hash_map<GdpKey, TaskInfoPtr, rt::_details::hash_compare_fix<GdpKey>>;
using TaskInfo_Vector = std::vector<TaskInfoPtr>;

extern GdpDataInMem* GDP_AllocDataInMem(const GdpHash& hash, LPCBYTE data, UINT data_len, UINT prefix_size, UINT suffix_size);

enum GdpDataFlag: DWORD
{
	GDF_NULL = 0,
	GDF_COLD_NORMAL,
	GDF_COLD_FREQUENT,
	GDF_HOT_NORMAL,
	GDF_HOT_FREQUENT,
};

struct GdpDataPage	// carry a single page of data, always aligned to (DATA_PAGESIZE)
{
	static const UINT	DATA_PAGESIZE = GDP_BLOB_PAGESIZE;

	std::string		_ColdData;

	UINT			DataTotalSize;
	UINT			PageNo;

	LPCBYTE			Data;
	UINT			DataSize;
	GdpDataFlag		Flag;	// GdpDataFlag

	GdpDataPage() { Data = nullptr; DataSize = 0; Flag = GDF_NULL; }
	void			Release() { _SafeDel_ConstPtr(this); }
	bool			IsColdData() const { return _ColdData.size(); }
	UINT			GetColdDataPadding() const;
};

using GdpDataMemLayout = ULONGLONG;
inline GdpDataMemLayout GdpMakeDataMemLayout(UINT PrefixSize = 0, UINT SuffixSize = 0) { return ((ULONGLONG)PrefixSize << 32) | SuffixSize; }
inline UINT				GdpGetPrefixSize(GdpDataMemLayout layout) { return layout >> 32; }
inline UINT				GdpGetSuffixSize(GdpDataMemLayout layout) { return layout & 0xffffffff; }

struct GdpPacketContext
{
	LPCVOID			pData;
	UINT			len;

	const NetworkAddress* from;

	GdpHint* _Hint;
	GdpHash* _Hash;
};


#define GDP_AUTO_COUNT(v) GdpCounter::_Counter_Holder MARCO_JOIN(_Counter_Holder,__COUNTER__)(v)

class GdpCounter
{
	volatile int _v = 0;

public:
	class _Counter_Holder
	{
		GdpCounter& _ct;

	public:
		FORCEINL _Counter_Holder(GdpCounter& counter) : _ct(counter) { _ct.Inc(); }
		FORCEINL ~_Counter_Holder() { _ct.Dec(); }
	};

public:
	FORCEINL int Inc() { return os::AtomicIncrement(&_v); }
	FORCEINL int Dec() { return os::AtomicDecrement(&_v); }
	FORCEINL int Val() { return _v; }
};

struct GdpWorkload
{
	uint64_t TotalCount;
	uint64_t TotalBytes;
	uint64_t FinishedCount;
	uint64_t FinishedBytes;
	uint64_t WorkingCount;
	uint64_t WorkingBytes;
	uint64_t DropedCount;
	uint64_t DropedBytes;
};


/////////////////////////////////////////////////////////
// Async data fetch
//
// all function supports async data fetch will return `osn_data` and has an argument of `const GdpAsyncDataFetch*`
// something like: 
// osn_data get_some_data(..., const GdpAsyncDataFetch* async_cb)
// 1. invoke with `async_cb = nullptr`: the function will do a blocking data fetch and return the actual data if available in local, otherwise the return `osn_data` will be empty
// 2. invole with an `async_cb` instance provided: the function will start async loading, the return `osn_data` will *always* be empty
//    2.1 if the data is available in local, the `GdpAsyncDataFetch::callback` will be called before `get_some_data` returns
//    2.2 if the data is not available in local, the `get_some_data` will first return with an empty `osn_data`
//       2.2.1 if the data is available in remote, `GdpAsyncDataFetch::callback` will be called with the actual fetched data
//       2.2.2 if the data is not found eventually, `GdpAsyncDataFetch::callback` will be called with `data = nullptr`

#pragma pack(push, 1)

struct GdpData
{
	uint32_t	Size;
	uint8_t*	Data;
};

typedef void (*GDP_FUNC_ON_FETCHED)(void* cookie, const GdpData* data);
struct GdpAsyncDataFetch
{
	GDP_FUNC_ON_FETCHED	Callback;
	void*				Cookie;
	uint32_t			Timeout;	// in milliseconds

	GdpAsyncDataFetch(){ Reset(); }
    void	Reset(){ Cookie =nullptr; Callback = nullptr; Timeout = 5000; }
	void	Invoke(const GdpData* data) const { if(Callback)Callback(Cookie, data); } // GdpData::Data shouldn't be held or freed by callee, who implements `callback`
	bool	IsEmpty() const { return Callback == nullptr; }
};

#pragma pack(pop)
} // namespace upw