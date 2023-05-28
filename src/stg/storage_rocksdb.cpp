#include "storage_rocksdb.h"

namespace upw
{
namespace _impl
{

upw::KVStoreValue RocksStorePaged::GetPaged(const upw::KVStoreKey* key, uint32_t page_no, std::string* workspace, uint32_t* total_size)
{
	ASSERT(key->Size == sizeof(GdpHash));
	auto* v = DB.GetPaged(*(GdpHash*)key->Data, page_no, *workspace);
	if(v)
	{
		if(total_size)*total_size = v->TotalSize;
		return { (uint8_t*)workspace->data() + DB.VALUE_PREFIX_SIZE, (uint32_t)workspace->size() - DB.VALUE_PREFIX_SIZE };
	}
	else return { nullptr, 0 };
}

bool RocksStorePaged::SaveAllPages(const upw::KVStoreKey* key, const upw::KVStoreValue* value)
{
	ASSERT(key->Size == sizeof(GdpHash));
	return DB.SetPaged(*(GdpHash*)key->Data, value->Data, value->Size);
}

upw::KVStoreValue RocksStorePaged::LoadAllPages(const upw::KVStoreKey* key, std::string* value)
{
	ASSERT(key->Size == sizeof(GdpHash));
	thread_local std::string first_page;
	auto* v = DB.GetPaged(*(GdpHash*)key->Data, 0, first_page);
	if(v)
	{
		value->resize(v->TotalSize);
		if(DB.LoadAllPages(*(GdpHash*)key->Data, v, value->data()))
			return { (uint8_t*)value->data(), v->TotalSize };
	}
	return { nullptr, 0 };
}

void RocksStorePaged::DeleteAllPages(const upw::KVStoreKey* key)
{
	ASSERT(key->Size == sizeof(GdpHash));
	DB.DeleteAllPages(*(GdpHash*)key);
}

class UnifiedStorageFactory: public itfc::StorageFactory
{
	friend struct RocksStore;
	friend struct RocksStorePaged;

protected:
	struct RocksStorageEntry
	{
		ext::RocksStorage	_Storage;
		volatile int		_StoreRefCount = 0;
	};

	rt::String			_MrcStorageDir;
	rt::String			_KvsStorageDir;
	rt::String			_MdsStorageDir;
	ext::RocksStorage	_MdsStorage;

protected:
	RocksMergeMode		_MrcStorageMode;
	RocksMergeMode		_KvsStorageMode;

	os::CriticalSection										_StoreMapCS;
	ext::fast_map_ptr<itfc::KVStore*, RocksStorageEntry>	_StoreMap;
	RocksStorageEntry*										_pSpecialMrcEntry = nullptr;	// used _MrcStorageMode == DEFAULT_DEDICATED
	RocksStorageEntry*										_pSpecialKvsEntry = nullptr; // used _KvsStorageMode == DEFAULT_DEDICATED

	RocksStorageEntry* _GetStorageEntry(const rt::String_Ref& mod_name, const rt::String_Ref& dir, RocksMergeMode mode, RocksStorageEntry*& special_entry, const DhtAddress* swarm_addr, bool default_swarm)
	{
		RocksStorageEntry* ret = nullptr;
		if(	mode == RocksMergeMode::All ||
			(mode == RocksMergeMode::Dedicated && default_swarm)
		)
		{
			ret = _New(RocksStorageEntry);
			ret->_StoreRefCount = 1;
			if(!ret->_Storage.Open(dir + '/' + mod_name +  '_' + tos(*swarm_addr)))
			{
				_SafeDel(ret);
				return nullptr;
			}

			return ret;
		}
		else
		{
			rt::String full_dir;
			if(mode == RocksMergeMode::Dedicated && !default_swarm)
				full_dir = dir + '/' + mod_name + rt::SS("_non_default");
			else
			{
				ASSERT(mode == RocksMergeMode::All);
				full_dir = dir + '/' + mod_name + rt::SS("_all_merged");
			}

			EnterCSBlock(_StoreMapCS);
			if(!special_entry)
			{
				ret = _New(RocksStorageEntry);
				ret->_StoreRefCount = 1;
				if(!ret->_Storage.Open(full_dir))
				{
					_SafeDel(ret);
					return nullptr;
				}
				special_entry = ret;
			}
			else
			{
				os::AtomicIncrement(&special_entry->_StoreRefCount);
			}

			return special_entry;
		}
	}

	template<typename T>
	itfc::KVStore* _AllocateStore(RocksStorageEntry* e, const rt::String_Ref& name, RocksMergeMode mode)
	{
		if(mode != RocksMergeMode::All)
		{
			itfc::KVStore* s = _New(T(e->_Storage.Get(name), this));

			EnterCSBlock(_StoreMapCS);
			ASSERT(_StoreMap.find(s) == _StoreMap.end());
			_StoreMap[s] = e;
			os::AtomicIncrement(&e->_StoreRefCount);
			return s;
		}
		else
			return _New(T(e->_Storage.Get(name)));
	}

protected:
	virtual	MrcMessageRelayStorage CreateMessageRelayStorage(const DhtAddress* swarm_addr, bool default_swarm) override
	{
		if(_MrcStorageDir.IsEmpty())return { nullptr, nullptr };
		if(_MrcStorageDir.StartsWith(rt::SS(":mem")))
		{
			return { AllocateMemoryKVStore(), AllocateMemoryKVStore() };
		}
		else
		{
			MrcMessageRelayStorage ret = { nullptr, nullptr };
			auto* e = _GetStorageEntry(rt::SS("mrc"), _MrcStorageDir, _MrcStorageMode, _pSpecialMrcEntry, swarm_addr, default_swarm);
			if(e)
			{
				ret.pPackets = _AllocateStore<RocksStore>(e, rt::SS("mrc/pk:") + tos(*swarm_addr), _MrcStorageMode);
				ret.pTimeHashIndex = _AllocateStore<RocksStore>(e, rt::SS("mrc/tmidx:") + tos(*swarm_addr), _MrcStorageMode);

				VERIFY(os::AtomicDecrement(&e->_StoreRefCount));
			}

			return ret;
		}
	}

	virtual DvsKeyValueStorage CreateDistributedValueStorge(const DhtAddress* swarm_addr, bool default_swarm) override
	{
		if(_KvsStorageDir.IsEmpty())return { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
		if(_KvsStorageDir.StartsWith(rt::SS(":mem")))
		{
			return { AllocateMemoryKVStorePaged(), AllocateMemoryKVStore(), AllocateMemoryKVStore(), AllocateMemoryKVStore(), AllocateMemoryKVStore(), AllocateMemoryKVStore() };
		}
		else
		{
			DvsKeyValueStorage ret = { nullptr, nullptr };
			auto* e = _GetStorageEntry(rt::SS("kvs"), _KvsStorageDir, _KvsStorageMode, _pSpecialKvsEntry, swarm_addr, default_swarm);
			if(e)
			{
				ret.pKeyValues = _AllocateStore<RocksStorePaged>(e, rt::SS("kvs/vals:") + tos(*swarm_addr), _KvsStorageMode);
				ret.pPendingPoW = _AllocateStore<RocksStore>(e, rt::SS("kvs/ppow:") + tos(*swarm_addr), _KvsStorageMode);
				ret.pMaintainedKeys = _AllocateStore<RocksStore>(e, rt::SS("kvs/kplv:") + tos(*swarm_addr), _KvsStorageMode);
				ret.pKeyValueMetadata = _AllocateStore<RocksStore>(e, rt::SS("kvs/vmta:") + tos(*swarm_addr), _KvsStorageMode);
				ret.pCachedKeyValues = _AllocateStore<RocksStore>(e, rt::SS("kvs/kvcc:") + tos(*swarm_addr), _KvsStorageMode);
				ret.pCachedKeyValueMetadata = _AllocateStore<RocksStore>(e, rt::SS("kvs/kvmc:") + tos(*swarm_addr), _KvsStorageMode);

				VERIFY(os::AtomicDecrement(&e->_StoreRefCount));
			}

			return ret;
		}
	}
	virtual MrcMediaRelayStorage CreateMediaRelayStorage() override
	{
		if(_MdsStorageDir.IsEmpty())return { nullptr, nullptr, nullptr, nullptr, nullptr };
		if(_MdsStorageDir.StartsWith(rt::SS(":mem")))
		{
			return { AllocateMemoryKVStorePaged(), AllocateMemoryKVStore(), AllocateMemoryKVStore(), AllocateMemoryKVStore(), AllocateMemoryKVStore() };
		}
		else
		{
			MrcMediaRelayStorage ret = { nullptr, nullptr, nullptr, nullptr, nullptr };
			ASSERT(!_MdsStorage.IsOpen());
			if(_MdsStorage.Open(_MdsStorageDir + rt::SS("/mds_db")))
			{
				ret.pBlobs = _New(RocksStorePaged(_MdsStorage.Get("mds/blob")));
				ret.pOffloads = _New(RocksStore(_MdsStorage.Get("mds/mtda")));
				ret.pBlobTimeHashIndex = _New(RocksStore(_MdsStorage.Get("mds/tmidx")));
				ret.pLocalBlobs = _New(RocksStore(_MdsStorage.Get("mds/lcbo")));
				ret.pKeySwarmMap = _New(RocksStore(_MdsStorage.Get("mds/swmap")));
			}

			return ret;
		}
	}

	virtual void Release() override
	{
		ASSERT(_StoreMap.size() == 0);
		ASSERT(_pSpecialMrcEntry == nullptr);
		ASSERT(_pSpecialKvsEntry == nullptr);
		_SafeDel_ConstPtr(this);
	}

	void KVStoreReleased(itfc::KVStore* store)
	{
		_StoreMapCS.Lock();
		auto* e = _StoreMap.get(store);
		ASSERT(e);
		_StoreMap.erase(store);
		if(os::AtomicDecrement(&e->_StoreRefCount) == 0)
		{
			_StoreMapCS.Unlock();
			if(e == _pSpecialMrcEntry)_pSpecialMrcEntry = nullptr;
			if(e == _pSpecialKvsEntry)_pSpecialKvsEntry = nullptr;
			_SafeDel(e);
		}
		else _StoreMapCS.Unlock();
	}

public:
	UnifiedStorageFactory(	const rt::String_Ref& mrc_dir, RocksMergeMode mrc_db_mode, const rt::String_Ref& mds_dir,
					const rt::String_Ref& kvs_dir, RocksMergeMode kvs_db_mode
	)	: _MrcStorageDir(mrc_dir), _MrcStorageMode(mrc_db_mode), _MdsStorageDir(mds_dir)
		, _KvsStorageDir(kvs_dir), _KvsStorageMode(kvs_db_mode)
	{	
	}		
};

RocksStore::~RocksStore()
{
	if(_pFactory)
	{
		DB.Empty();
		_pFactory->KVStoreReleased(this);
	}
}

RocksStorePaged::~RocksStorePaged()
{
	if(_pFactory)
	{
		DB.Empty();
		_pFactory->KVStoreReleased(this);
	}
}

} // namespace _impl

itfc::StorageFactory* AllocateUnifiedStorageFactory(
	const rt::String_Ref& mrc_dir, RocksMergeMode mrc_db_mode, const rt::String_Ref& mds_dir,
	const rt::String_Ref& kvs_dir, RocksMergeMode kvs_db_mode
)
{
	return _New(_impl::UnifiedStorageFactory(mrc_dir, mrc_db_mode, mds_dir, kvs_dir, kvs_db_mode));
}

} // namespace upw