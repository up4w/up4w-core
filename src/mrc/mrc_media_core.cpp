#include "../netsvc_core.h"
#include "../gdp/gdp.h"
#include "../swarm_broadcast.h"
#include "mrc.h"
#include "mrc_message.h"
#include "mrc_media_core.h"

#if defined(PLATFORM_RELEASE_BUILD) || defined(PLATFORM_SUPPRESS_DEBUG_LOG)
#define HVS_LOG(X) {}
#define HVS_TRACE(X) {}
#else
#define HVS_LOG(X) if(_details::_LogMode >= _details::HLS_LOG) _LOGC("[DAG]: " << os::Timestamp::Get() << ": " << X)
#define HVS_TRACE(X) if(_details::_LogMode >= _details::HLS_TRACE) _LOGC("[DAG]: " << os::Timestamp::Get() << ": " << X)
#define HVS_BIN_TO_BASE16(T) (rt::tos::Base16OnStack<>(T))
#endif


namespace upw
{
using namespace ext;

static const GdpHint MRC_HINT = { 0x2200 };

namespace _details
{
class MrcMediaBlobPow
{
	BYTE		_Data[64];
	void		_CalcSha512(const MrcMediaOffload& entry)
				{
					auto& h = GetSha512Hasher();
					h.Update(&entry, offsetof(MrcMediaOffload, PowNonce));
					h.Finalize(_Data);
				}
public:
	static uint64_t	PowHashCount(uint32_t att_size, uint16_t ttl_day, uint16_t pow_factor = 1)
				{
					return pow_factor * 
						   ( 10ULL*1024 + 
							 10ULL*rt::min<ULONGLONG>(16ULL*1024, att_size) +
							 (att_size>16*1024 ? (att_size-16*1024) : 0) +
							 (att_size+1024)*ttl_day/256);
				}
	uint64_t	SearchNonce(const MrcMediaOffload& entry)
				{
					_CalcSha512(entry);
					MrcPowDifficulty pow(PowHashCount(entry.Size, entry.DTL));
					return pow.SearchNonce(_Data);
				}
	bool		IsValid(const MrcMediaOffload& entry)
				{
					_CalcSha512(entry);
					MrcPowDifficulty pow(PowHashCount(entry.Size, entry.DTL));
					return pow.IsFulfilled(_Data, entry.PowNonce);
				}
};

#if defined(PLATFORM_RELEASE_BUILD) || defined(PLATFORM_SUPPRESS_DEBUG_LOG)
#else
enum MrcMediaLogMode
{
	HLS_OFF = 0,
	HLS_ON = 1,
	HLS_LOG = 1,
	HLS_TRACE = 2,
};
extern MrcMediaLogMode _LogMode = HLS_TRACE;
#endif

};

#pragma pack(push, 1)
struct TimeHashKey
{
	TYPETRAITS_DECLARE_POD;
	rt::BigEndianNumber<int64_t, false>		Time;
	GdpHash									Hash;
};
#pragma pack(pop)

MrcMediaRelayCore::DataRelayCBS::LoadRecord::LoadRecord(const GdpAsyncDataFetch* async_cb) 
{ 
	pNext = nullptr;
	if(async_cb)
		Async = *async_cb;
	else
		Async.Reset();
}

void MrcMediaRelayCore::DataRelayCBS::Append(const HashValue& key, const GdpAsyncDataFetch* async_cb)
{
	if(!async_cb || async_cb->IsEmpty()) 
		return;

	LoadRecord* rec = _New(LoadRecord(async_cb));

	auto it = _Map.find(key);
	if(it!= _Map.end())
	{
		rec->pNext = it->second;
	}

	_Map[key] = rec;
}

void MrcMediaRelayCore::DataRelayCBS::Invoke(const HashValue& key, const GdpData* data)
{
	if(_Map.count(key))
	{
		LoadRecord* rec = _Map[key];
		_Map.erase(key);
		LoadRecord* node;
		while(rec)
		{
			rec->Async.Invoke(data);
			node = rec;
			rec = rec->pNext;
			_SafeDel_ConstPtr(node);
		}
	}
}

void MrcMediaRelayCore::DataRelayCBS::CancelAll(GossipDataPropagation* gdp)
{
	GdpData* data = nullptr;
	for(auto& it : _Map)
	{
		if(gdp)
		{
			HashValue hash = it.first;
			gdp->RemoveDownloadTask(hash, MRC_HINT);
		}

		LoadRecord* rec = it.second;
		LoadRecord* node;
		while(rec)
		{
			rec->Async.Invoke(data);
			node = rec;
			rec = rec->pNext;
			_SafeDel_ConstPtr(node);
		}
	}
	_Map.clear();
}

MrcMediaRelayCore::MrcMediaRelayCore(MessageRelayCore& node)
	:_Node(node)
{
	_Workload = { 0 };
	_pNet = _Node.Net();
	_Suspended = false;
	_bInit = false;
}

void MrcMediaRelayCore::_RemoveOffload(MrcMediaOffloadItem& offload)
{
	// only delete offloads without secret
	if(offload.SecretHash.IsZero())
	{
		_Offloads.Delete(offload.Hash);
		_Workload.TotalCount--;
		_Workload.TotalBytes -= offload.Size;
	}

	if(_Blobs.Has(offload.Hash))
	{
		_Blobs.DeleteAllPages(offload.Hash);
		_Workload.AvailableCount--;
		_Workload.AvailableBytes -= offload.Size;
	}
}

void MrcMediaRelayCore::_Thrink()
{
	if(!_bInit || _Suspended)
		return;

	EnterCSBlock(_CoreCS);
	
	if(_Blobs.IsEmpty() || _TimeHashIndex.IsEmpty())
		return;

	if(_MissedHash.size() > MRC_MEDIA_MISSING_CACHE_SIZE)
		_MissedHash.clear();

	int64_t now = os::Timestamp::Get();

	for(auto it = _TimeHashIndex.First(); it.IsValid();)
	{
		auto key = it.Key<TimeHashKey>();
		if(now < key.Time) break;

		it.Next(); // Delete-OP may cause iterator invalidation

		_TimeHashIndex.Delete(key);

		MrcMediaOffloadItem offload;
		if(_Offloads.GetAs<MrcMediaOffloadItem>(key.Hash, &offload))
		{
			if(offload.ExpirationTime() < now)
				_RemoveOffload(offload);
		}
	}
}

uint32_t MrcMediaRelayCore::_GetSwarmIds(const GdpHash& hash, rt::BufferEx<UINT>& swarm_ids)
{
	thread_local std::string buf;
	swarm_ids.Clear();

	if(_KeySwarmMap.Get(hash, buf) && buf.length() % sizeof(DhtAddress) == 0)
	{
		size_t n = buf.length() / sizeof(DhtAddress);
		DhtAddress* addr = (DhtAddress*)buf.data();
		for(auto i = 0; i < n; i++)
		{
			uint32_t id = addr[i].IsZero() ?
							_DefaultSwarmId :
							_pNet->SMB().GetSwarmIdFromAddress(addr[i]);

			if(id)swarm_ids.push_back(id);
		}

		return swarm_ids.GetSize();
	}

	return 0;
}

void MrcMediaRelayCore::_Retrieve(const GdpHash* hash, uint8_t priority)
{
	thread_local rt::BufferEx<UINT> swarm_ids;

	if(!_bInit || _Suspended)
		return;

	EnterCSBlock(_CoreCS);

	if(_Blobs.IsEmpty() || _TimeHashIndex.IsEmpty())
		return;

	if(hash) // only retrieve one item 
	{
		if(!_Blobs.Has(*hash)) // check exist
		{
			if(_GetSwarmIds(*hash, swarm_ids) > 0) // get available swarms
			{
				for(auto i = 0; i < swarm_ids.GetSize(); i++)
					_pGDP->Request(swarm_ids[i], hash, 1, MRC_HINT, { MRC_MEDIA_BLOB_MAXSIZE, 0, priority, 0 });

				HVS_LOG(HVS_BIN_TO_BASE16(*hash) << " lost, trying ...");
			}
		}
		return;
	}

	HVS_LOG("MrcMediaRelayCore Check:");
	int64_t now = os::Timestamp::Get();

	for(auto it = _Offloads.First(); it.IsValid(); )
	{
		HashValue key = it.Key<HashValue>();
		KVStoreData val = it.GetValue();

		it.Next();

		if(val.Size != sizeof(MrcMediaOffloadItem))
		{
			_Offloads.Delete(key);
			continue;
		}

		auto& value = val.To<MrcMediaOffloadItem>();

		if(value.ExpirationTime() < now)
		{
			_Offloads.Delete(key);
			continue;
		}

		if(!_Blobs.Has(key))
		{
			HVS_LOG(HVS_BIN_TO_BASE16(key) << " lost, trying ...");
			if(_GetSwarmIds(key, swarm_ids) > 0)
			{
				for(auto i = 0; i < swarm_ids.GetSize(); i++)
					_pGDP->Request(swarm_ids[i], (const GdpHash*)&key, 1, MRC_HINT, { MRC_MEDIA_BLOB_MAXSIZE, 0, priority, 0 });
			}
			else
			{
				_pGDP->Request(_DefaultSwarmId, (const GdpHash*)&key, 1, MRC_HINT, { MRC_MEDIA_BLOB_MAXSIZE, 0, priority, 0 });
			}
		}
		else
		{
			HVS_LOG(HVS_BIN_TO_BASE16(key) << " ok");
		}

	}
}

void MrcMediaRelayCore::OnTick(UINT tick)
{
	if(!_bInit || _Suspended)
		return;

	// 10 minutes
	if(tick % (10*60*10) == 5*60*10)
		_Thrink();

	// 1 minute
	if(tick % (60 * 10) == 5*60)
		_Retrieve(nullptr, MMP_RETRY);
}

void MrcMediaRelayCore::_Set(const GdpHash& h, const void* data, uint32_t size)
{
	if(!_bInit)
		return;

	MrcMediaOffloadItem offload;
	if(!LoadMediaOffloaded(h, offload))
		return;

	{	EnterCSBlock(_CoreCS);
		_MissedHash.erase(*(GdpHash*)h.Bytes);
	}

	if(!_Blobs.Has(h))
	{
		_Blobs.SaveAllPages(h, KVStoreData(data, size));
		_Workload.AvailableCount++;
		_Workload.AvailableBytes += size;

		// first time recv, broadcast it
		rt::BufferEx<UINT> ids;
		if(_GetSwarmIds(h, ids))
		{
			for(SIZE_T i=0;i<ids.GetSize();i++)
				_pGDP->Broadcast(ids[i], nullptr, 0, h, MRC_HINT, 1);
		}
		// todo: 
	}

	if(offload.SecretHash.IsZero())return;
	if(_LocalBlobs.Has(h))return;

	Cipher cipher(offload.SecretHash);
	rt::BufferEx<BYTE> buf_dst;
	buf_dst.SetSize(size);
	cipher.Decode(data, buf_dst.Begin(), size, offload.SecretHash.DWords[0]);

	// cache raw data 
	_LocalBlobs.Set(h, KVStoreData(buf_dst.Begin(), offload.OriginalSize()));

	GdpData cdata = { offload.OriginalSize(), buf_dst.Begin() };
	_CBS.Invoke(h, &cdata);
}

bool MrcMediaRelayCore::Init(UINT default_swarm_id, const MrcMediaRelayStorage& storage, bool bInitSuspended)
{
	EnterCSBlock(_CoreCS);
	_Suspended = bInitSuspended;

	ASSERT(_Blobs.IsEmpty() && _Offloads.IsEmpty() && _TimeHashIndex.IsEmpty());

	_Blobs = storage.pBlobs; // .Get(MRC_MEDIA_HASH_BLOB_TABLE);
	_Offloads = storage.pOffloads; // .Get(MRC_MEDIA_HASH_OFFLOADED_TABLE);
	_TimeHashIndex = storage.pBlobTimeHashIndex; // .Get(MRC_MEDIA_TIMEHASH_INDEX);
	_LocalBlobs = storage.pLocalBlobs; // .Get(MRC_MEDIA_HASH_BLOB_READ_TABLE);
	_KeySwarmMap = storage.pKeySwarmMap; // .Get(MRC_MEDIA_HASH_SWARMS_TABLE);

	ASSERT(storage.pBlobs->GetPagedKeySize() == sizeof(GdpHash));
	ASSERT(storage.pBlobs->GetPagedSize() == MRC_MEDIA_BLOB_PAGESIZE);

	if(!_Blobs.IsEmpty() && !_Offloads.IsEmpty() && !_TimeHashIndex.IsEmpty() && !_LocalBlobs.IsEmpty() && !_KeySwarmMap.IsEmpty())
	{
		//SummaryRocksDB(_Blobs, "MrcMediaRelayCore::_Blobs", sizeof(GdpHash));
		//SummaryRocksDB(_Offloads, "MrcMediaRelayCore::_Offloads");
		//SummaryRocksDB(_TimeHashIndex, "MrcMediaRelayCore::_TimeHashIndex");
		//SummaryRocksDB(_LocalBlobs, "MrcMediaRelayCore::_LocalBlobs");

		_bInit = true;

		ASSERT(default_swarm_id);
		_DefaultSwarmId = default_swarm_id;

		_CalcWorkload();

		_pGDP = &_pNet->GDP();
		_GDP_LOG_STATUS_ = GLS_LOG;

		_pNet->GDP().SetOnDataCallback(
			MRC_HINT.Module,
			this,
			&MrcMediaRelayCore::_GdsDataRecvAssembled,
			&MrcMediaRelayCore::_GdsDataRecvUnfragmented,
			&MrcMediaRelayCore::_GdsDataDiscovered,
			&MrcMediaRelayCore::_GdsDataRequest
		);
		return true;
	};

	Term();
	return false;
}

void MrcMediaRelayCore::Term()
{
	_bInit = false;

	EnterCSBlock(_CoreCS);
	_pNet->GDP().SetOnDataCallback(MRC_HINT.Module, nullptr);

	_CBS.CancelAll(_pGDP);
	_Blobs.Empty();
	_Offloads.Empty();
	_TimeHashIndex.Empty();
	_LocalBlobs.Empty();
	_KeySwarmMap.Empty();	
}

GdpDataMemLayout MrcMediaRelayCore::_GdsDataDiscovered(const GdpHash& hash, const GdpHint& hint, LPCBYTE sample, UINT sample_len, UINT data_len)
{
	if(!_bInit || _Suspended || data_len > MRC_MEDIA_BLOB_MAXSIZE)
		return 0;

	if(_Blobs.Has(hash))return 0;
	return GdpMakeDataMemLayout(sizeof(GdpDataInMem::PrefixHeader), 0);
}

bool MrcMediaRelayCore::_GdsDataRecvUnfragmented(const GdpHash& hash, const GdpHint& hint, LPBYTE data, UINT data_len)
{
	if(!_bInit || _Suspended)
		return 0;

	_Set(hash, data, data_len);
	return true;
}

bool MrcMediaRelayCore::_GdsDataRecvAssembled(GdpDataInMem* data, const GdpHint& hint)
{
	if(!_bInit || _Suspended)
		return 0;

	_Set(data->Header.Hash,  data->Mem+sizeof(GdpDataInMem::PrefixHeader), data->Header.DataLen);

	_SafeFree8AL_ConstPtr(data);
	return true;
}

GdpDataPage* MrcMediaRelayCore::_GdsDataRequest(const GdpHash& hash, const GdpHint& hint, UINT page_no)
{
	if(!_bInit || _Suspended || _MissedHash.count(hash))
		return nullptr;

	EnterCSBlock(_CoreCS);

	if (!_Blobs.Has(hash))
	{
		_MissedHash.insert(hash);
		return nullptr;
	}

	GdpDataPage* lpDataPage = _New(GdpDataPage);

	uint32_t total;
	auto val = _Blobs.GetPaged(hash, page_no, &lpDataPage->_ColdData, &total);
	if(val.Data)
	{
		lpDataPage->DataTotalSize = total;
		lpDataPage->DataSize = val.Size;
		lpDataPage->Data = val.Data;
		lpDataPage->PageNo = page_no;
		lpDataPage->Flag = GDF_COLD_NORMAL;

		return lpDataPage;
	}

	_SafeDel(lpDataPage);
	return nullptr;
	
}

bool MrcMediaRelayCore::_Load(const GdpHash& key, std::string& out, const GdpAsyncDataFetch* async_cb, uint8_t priority)
{
	if(!_bInit)
	{
		GdpData cdata = { 0, nullptr };
		if(async_cb)async_cb->Invoke(&cdata);

		return false;
	}

	EnterCSBlock(_CoreCS);

	if(_Blobs.IsEmpty())
	{
		if(async_cb)
			async_cb->Invoke(nullptr);

		return false;
	}

	if(_Blobs.LoadAllPages(key, &out).Data)
		return true;

	_CBS.Append(key, async_cb);
	_pGDP->Request(_DefaultSwarmId, &key, 1, MRC_HINT, { MRC_MEDIA_BLOB_MAXSIZE, 0, priority, 0});
	return false;
}

bool MrcMediaRelayCore::CheckOffloadPow(MrcMediaOffloadItem& offload)
{
	return CheckOffloadPow(*(MrcMediaOffload*)&offload);
}

bool MrcMediaRelayCore::CheckOffloadPow(MrcMediaOffload& offload)
{
	return _details::MrcMediaBlobPow().IsValid(offload);
}

bool MrcMediaRelayCore::CheckOffloadPow(const MrcMediaOffload& offload)
{
	return CheckOffloadPow(*(MrcMediaOffload*)&offload);
}

bool MrcMediaRelayCore::Save(uint8_t mime, const GdpData& data, MrcMediaOffloadItem& out, const DhtAddress* swarms, uint32_t swarm_count)
{
	if( !_bInit ||  data.Size == 0 || data.Size > MRC_MEDIA_BLOB_MAXSIZE)
		return false;

	MrcMediaOffloadItem& offload = out;

	// hash of raw data is the secret
	offload.SecretHash.Hash(data.Data, data.Size);

	// if encrypt, offload.hash will be replaced by hash of encypted data
	offload.Hash = offload.SecretHash; 
	offload.ContentType = mime;
	offload.MinuteStamp = _Node.GetTime() / (1000 * 60);
	offload.DTL = (MRC_PACKETS_DB_DURATION * 1.5) / (1000ULL*60*60*24);
	offload.PowNonce = 0;

	Cipher cipher(offload.SecretHash);
	offload.Size = cipher.AlignSize(data.Size);

	rt::BufferEx<BYTE> buf;
	buf.SetSize(offload.Size);
	offload.Padding = offload.Size - data.Size;
	memcpy(buf.Begin(), data.Data, data.Size);
	memset(buf.Begin() + data.Size, 0, offload.Padding);

	rt::BufferEx<BYTE> buf_dst;
	buf_dst.SetSize(buf.GetSize());
	cipher.Encode(buf.Begin(), buf_dst.Begin(), buf.GetSize(), offload.SecretHash.DWords[0]);

	//JP: Calculate will do Reset as well
	offload.Hash.Hash(buf_dst.Begin(), buf_dst.GetSize());

	// Calc POW
	offload.PowNonce = _details::MrcMediaBlobPow().SearchNonce(offload);

	// cache raw data 
	_LocalBlobs.Set(offload.Hash, KVStoreData(data.Data, data.Size));

	// update swarm info
	_UpdateDataSwarmInfo(offload.Hash, swarms, swarm_count);

	MediaOffloadDiscovered(*(const MrcMediaOffload*)&offload, &offload.SecretHash, nullptr); // swarm info had updated, pass nullptr 

	_Save(offload.Hash, buf_dst.Begin(), offload.Size);

	return true;
}

void MrcMediaRelayCore::_Save(const GdpHash& h, LPCVOID data, UINT size)
{
	_Set(h, data, size);
}

bool MrcMediaRelayCore::LoadMediaOffloaded(const GdpHash& encrypted_data_hash, MrcMediaOffloadItem& offload)
{
	if(!_bInit)
		return false;

	return _Offloads.GetAs<MrcMediaOffloadItem>(encrypted_data_hash, &offload);
}

bool MrcMediaRelayCore::_LoadAsync(const GdpHash& hash, rt::BufferEx<BYTE>& buf_dst, const GdpAsyncDataFetch* async_cb, uint8_t priority)
{
	thread_local std::string temp;

	GdpData cb_data = { 0, nullptr };
	bool cb_byself = true;

	if(_bInit)
	{	
		if(_LocalBlobs.Get(hash, temp)) // find in local cache , it's decrypted
		{
			HVS_LOG("MrcMediaRelayCore::_LoadAsync() from LocalBlobs");

			buf_dst.SetSize(temp.size());
			buf_dst.CopyFrom(temp.data());

			cb_data = { (uint32_t)buf_dst.GetSize(), buf_dst.Begin()};
		}
		else
		{
			MrcMediaOffloadItem offload;
			if(_Offloads.GetAs<MrcMediaOffloadItem>(hash, &offload) && !offload.SecretHash.IsZero()) // check MrcMediaOffloadItem valid
			{
				HVS_LOG("MrcMediaRelayCore::_LoadAsync() from HVS");

				if(_Load(hash, temp, async_cb, priority)) // find in relay db , it's encrypted
				{
					Cipher cipher(offload.SecretHash);
					buf_dst.SetSize(temp.size());
					cipher.Decode(temp.data(), buf_dst.Begin(), (uint32_t)temp.size(), offload.SecretHash.DWords[0]);

					buf_dst.ShrinkSize(offload.OriginalSize());

					// cache raw data 
					_LocalBlobs.Set(offload.Hash, KVStoreData(buf_dst.Begin(), buf_dst.GetSize()));

					cb_data = { (uint32_t)buf_dst.GetSize(), buf_dst.Begin() };
				}
				else
				{
					// will callback with decrypted data
					cb_byself = false;
				}
			}
		}
	}

	if (cb_byself && async_cb)
		async_cb->Callback(async_cb->Cookie, &cb_data);
	
	return (cb_data.Size && cb_data.Data);
}

GdpData MrcMediaRelayCore::Load(const GdpHash& hash, const GdpAsyncDataFetch* async_cb, uint8_t priority)
{
	rt::BufferEx<BYTE> buf_dst;
	if (_LoadAsync(hash, buf_dst, async_cb, priority))
		return { (uint32_t)buf_dst.GetSize(), buf_dst.Detach() };
	else
		return {0, nullptr};
}

int MrcMediaRelayCore::GetAvailability(const GdpHash& hash)
{
	if(!_bInit) return -1;

	// in local cache?
	if(_LocalBlobs.Has(hash)) return 1000;

	// in hvs?
	if(_Blobs.Has(hash)) return 1000;

	// offload exist?
	MrcMediaOffloadItem offload;
	if(!_Offloads.GetAs<MrcMediaOffloadItem>(hash, &offload) || offload.SecretHash.IsZero())
		return -1;

	GdpDownloadTaskStatus status;
	if(_pGDP->QueryDownloadTask(hash, MRC_HINT, status))
		return	rt::min(999, 
					rt::max(1, ((int)(status.Downloaded * 1000ULL / status.DataLen)))
				);

	return 0;
}

bool MrcMediaRelayCore::Export(const GdpHash& hash, const char* dest, rt::String* opt_final_path)
{
	thread_local rt::BufferEx<BYTE> temp;
	thread_local rt::String file_content;

	if(!_bInit) return false;

	// if not exist, must be ready in 10*100ms
	int ct = 10;
	while(ct)
	{
		if(Load(hash, temp))
			break;

		if(--ct) os::Sleep(100);
	}

	if(!ct) return false;

	if(opt_final_path)
	{
		rt::String filename(dest);
		rt::String_Ref ext = filename.GetExtName();
		rt::String_Ref fnmain = filename.TrimRight(ext.GetLength());
	
		rt::String fn_probe = filename;

		// probe filename
		for(int i = 0; i < 100; i++)
		{
			if(i != 0)
				fn_probe = fnmain + "_" + rt::tos::Number(i) + ext;
			else
				fn_probe = fnmain + ext;

			if(!os::File::IsExist(fn_probe)) break; // not exist, can be used

			auto file_len = os::File::GetFileSize(fn_probe);
			if(file_len > MRC_MEDIA_BLOB_MAXSIZE || file_len != temp.GetSize()) continue; // another file exist, try next

			// check file content
			if(os::File::LoadBinary(fn_probe, file_content)
				&& memcmp(temp.Begin(), file_content.Begin(), file_len) == 0
			)
			{	// find same file!
				rt::Swap(*opt_final_path, fn_probe);
				return true;
			}
		}

		if(os::File::SaveBinary(fn_probe, rt::String_Ref((char*)temp.Begin(), temp.GetSize())))
		{
			rt::Swap(*opt_final_path, fn_probe);
			return true;
		}
		
		return false;
	}

	return os::File::SaveBinary(dest, rt::String_Ref((char*)temp.Begin(), temp.GetSize()));
}

bool MrcMediaRelayCore::MediaOffloadDiscovered(const MrcMediaOffload& entry, const GdpHash* secret, const DhtAddress* swarm_addr)
{
	// todo: return false if data is invalid, e.g. pow not fulfilled
	if(!_bInit || !CheckOffloadPow(entry))
		return false;

	if(secret && secret->IsZero())
		return false;

	MrcMediaOffloadItem offload;
	bool updated = false;
	//bool update_secret = true;

	_UpdateDataSwarmInfo(entry.Hash, swarm_addr?swarm_addr:&DhtAddress::ZeroValue(), 1);

	if(_Offloads.GetAs<MrcMediaOffloadItem>(entry.Hash, &offload))
	{
		if(entry.MinuteStamp > offload.MinuteStamp &&
			(
				entry.ContentType != offload.ContentType ||
				entry.Padding != offload.Padding ||
				entry.Size != offload.Size ||
				(secret && *secret != offload.SecretHash)
			)
		)
		{	offload.Padding = entry.Padding;
			offload.ContentType = entry.ContentType;
			offload.Size = entry.Size;
			if (secret)
				offload.SecretHash = *secret;
			updated = true; 
		}
		else if(secret && offload.SecretHash.IsZero())
		{
			offload.SecretHash = *secret;
			updated = true;
		}

		if(offload.ExpirationTime() < entry.ExpirationTime())
		{
			_TimeHashIndex.Delete(TimeHashKey{offload.ExpirationTime(), offload.Hash});

			offload.MinuteStamp = entry.MinuteStamp;
			offload.MinuteStamp = entry.MinuteStamp;
			updated = true;

			_TimeHashIndex.Set(TimeHashKey{offload.ExpirationTime(), offload.Hash}, {});
		}

		if(updated)
			_Offloads.Set(offload.Hash, offload);
	}
	else
	{
		_Workload.TotalCount++;
		_Workload.TotalBytes += entry.Size;

		rt::Copy((MrcMediaOffload&)offload, entry);
		_Retrieve(&entry.Hash, (secret ? MMP_USER_DATA : MMP_ANONYMOUS_DATA));

		if (secret)
			offload.SecretHash = *secret;
		else
			offload.SecretHash.Zero();

		_TimeHashIndex.Set(TimeHashKey{offload.ExpirationTime(), offload.Hash}, {});
		 _Offloads.Set(offload.Hash, offload);
	}

	return true;
}

bool MrcMediaRelayCore::RetainExistingOffload(const GdpHash& hash, uint32_t ttl_days, MrcMediaOffloadItem& out)
{
	if(!_bInit)
		return false;

	if(!_Offloads.GetAs<MrcMediaOffloadItem>(hash, &out) || out.SecretHash.IsZero())
		return false;

	if(!_Blobs.Has(hash))
	{	// revive media blob
		std::string data;
		data.reserve(out.Size);
		if(!_LocalBlobs.Get(hash, data))
			return false;

		ASSERT(data.max_size() >= out.Size);
	
		Cipher cipher(out.SecretHash);
		if(	out.Size != cipher.AlignSize(data.size()) ||
			out.Padding != out.Size - data.size()
		)	return false;

		memset(data.data() + data.size(), 0, out.Padding);

		rt::BufferEx<BYTE> buf_dst;
		buf_dst.SetSize(out.Size);
		cipher.Encode(data.data(), buf_dst.Begin(), out.Size, out.SecretHash.DWords[0]);
		_Blobs.SaveAllPages(out.Hash, KVStoreData(buf_dst.Begin(), out.Size));
	}

	if(out.ExpirationTime() < _pNet->GetNetworkTime() + (ttl_days*1000LL * 60 * 60 * 24))
	{
		// refresh PoW
		out.MinuteStamp = _pNet->GetNetworkTime() / (1000 * 60);
		out.DTL = ttl_days;
		out.PowNonce = _details::MrcMediaBlobPow().SearchNonce(out);
	}

	return true;
}

void MrcMediaRelayCore::GetWorkload(rt::String& out)
{
	auto ret = GetWorkload();

	out += (
		J(HVS_TotoalCount) = ret.TotalCount,
		J(HVS_TotalBytes) = ret.TotalBytes,
		J(HVS_MissingCount) = ret.MissingCount,
		J(HVS_MissingBytes) = ret.MissingBytes
		);
}

MrcMediaWorkload MrcMediaRelayCore::GetWorkload()
{
	_Workload.MissingCount = _Workload.TotalCount > _Workload.AvailableCount ?
		_Workload.TotalCount - _Workload.AvailableCount : 0;
	_Workload.MissingBytes = _Workload.TotalBytes > _Workload.AvailableBytes ?
		_Workload.TotalBytes - _Workload.AvailableBytes : 0;
	return _Workload;
}

void MrcMediaRelayCore::_UpdateDataSwarmInfo(const GdpHash& hash, const DhtAddress* swarms, uint32_t swarm_count)
{
	ASSERT(swarm_count);

	std::string buf;
	if(_KeySwarmMap.Get(hash, buf))
	{
		if(buf.length() % sizeof(DhtAddress) != 0)
			buf.clear();
	}
	else
		buf.clear();
	
	int added = 0;
	for(uint32_t i = 0; i < swarm_count; i++)
	{
		size_t n = buf.length() / sizeof(DhtAddress);
		DhtAddress* saved_addr = (DhtAddress*)buf.data();
		bool found = false;
		for(auto j = 0; j < n; j++)
			if(swarms[i] == saved_addr[j])
			{
				found = true;
				break;
			}
		if(found) continue;
		buf.append((char*)(swarms + i), sizeof(DhtAddress));
		added++;
	}
			
	if(added)
	{
		_KeySwarmMap.Set(hash, KVStoreData(buf.data(), (uint32_t)buf.length()));
	}
}

void MrcMediaRelayCore::_CalcWorkload()
{
	_Workload = { 0 };
	
	if(_Blobs.IsEmpty() || _TimeHashIndex.IsEmpty() || _Offloads.IsEmpty())
		return;

	int64_t now = os::Timestamp::Get();
	for(auto it = _Offloads.First(); it.IsValid(); it.Next())
	{
		auto& key = it.Key<GdpHash>();
		auto& value = it.Value<MrcMediaOffloadItem>();

		if(value.ExpirationTime() < now)
			continue;

		_Workload.TotalCount++;
		_Workload.TotalBytes += value.Size;

		if(_Blobs.Has(key))
		{
			_Workload.AvailableCount++;
			_Workload.AvailableBytes += value.Size;
		}
	}
}

void MrcMediaRelayCore::CancelPendingLoads(bool clear_gds)
{
	EnterCSBlock(_CoreCS);
	_CBS.CancelAll(clear_gds?_pGDP:nullptr);
}

void MrcMediaRelayCore::CleanUnusefulData(os::ProgressReport& prog)
{
	EnterCSBlock(_CoreCS);

	if(_Blobs.IsEmpty() || _TimeHashIndex.IsEmpty() || _Offloads.IsEmpty())
		return;

	// collect all hashes in time_hash_index
	rt::hash_set<HashValue> rec_hash;
	for(auto it = _TimeHashIndex.First(); it.IsValid(); it.Next())
	{
		auto& key = it.Key<TimeHashKey>();
		rec_hash.insert(key.Hash);
	}

	prog.SetProgress(10);

	// collect all hashes in offloads
	int64_t now = os::Timestamp::Get();
	rt::hash_set<HashValue> offload_hash;
	for(auto it = _Offloads.First(); it.IsValid(); it.Next())
	{
		auto& key = it.Key<GdpHash>();
		auto& value = it.Value<MrcMediaOffloadItem>();

		if(value.ExpirationTime() < now)
			continue;

		offload_hash.insert(key);

		if(rec_hash.count(key) == 0)
		{
			HVS_LOG("TimeIndex miss Hash, reset it");
			_TimeHashIndex.Set(TimeHashKey{value.ExpirationTime(), value.Hash}, {});
		}
	}

	prog.SetProgress(25);

	// todo: search all chats message & find unuseful local blobs
	{
		int64_t all_size = 0;
		int64_t all_count = 0;
		for(auto it = _LocalBlobs.First(); it.IsValid(); it.Next())
		{
			all_size += it.GetValue().Size;
			all_count++;
		}

		HVS_LOG("local blob cache total size: " << all_size << ", count:" << all_count);
	}

	prog.SetProgress(30);

	// clean untracked blobs
	{	auto s = prog.SubScope(70);
		prog.SetProgressRange(offload_hash.size());

		int64_t all_size = 0;
		int64_t all_count = 0;
		int64_t untracked_size = 0;
		int64_t untracked_count = 0;
		
		for(auto it = _Blobs.First(); it.IsValid();)
		{
			auto raw_key = it.GetKey();
			HashValue key = it.Key<HashValue>();
			auto value_size = it.GetValue().Size;

			it.Next();

			if(offload_hash.count(key) == 0)
			{
				untracked_size += value_size;
				untracked_count++;

				_Blobs.Delete(raw_key);
				prog.MakeProgress();
			}

			all_size += value_size;
			all_count++;
		}
		HVS_LOG("global blob total size: " << all_size << ", count:" << all_count);
		HVS_LOG("global blob untracked size: " << untracked_size << ", count:" << untracked_count);
	}
}

} // namespace upw
