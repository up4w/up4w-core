#include "storage_interface.h"
#include "../gdp/gdp_base.h"
#include "../mrc/mrc_base.h"


namespace upw
{
namespace _impl
{

template<typename KEY>
class KVStoreIterator: public itfc::KVStoreIterator
{
	os::CriticalSection&		_CS;
	std::map<KEY, std::string>&	_Map;
	typename std::map<KEY, std::string>::iterator _Iter;

public:
	KVStoreIterator(os::CriticalSection& cs, std::map<KEY, std::string>& map, const KEY& seek_key)
		:_CS(cs), _Map(map), _Iter(map.find(seek_key)){ ASSERT(_CS.IsLockedByCurrentThread()); }
	KVStoreIterator(bool first_or_last, os::CriticalSection& cs, std::map<KEY, std::string>& map)
		:_CS(cs), _Map(map), _Iter(first_or_last?map.begin():std::prev(map.end())){ ASSERT(_CS.IsLockedByCurrentThread()); }
	~KVStoreIterator(){ _CS.Unlock(); }

	virtual bool			IsValid() override { return _Iter != _Map.end(); }
	virtual void			Next() override { _Iter++; }
	virtual void			Prev() override { _Iter--; }
	virtual KVStoreKey		GetKey() override 
							{	if constexpr (rt::TypeTraits<KEY>::IsPOD){ return { (uint8_t*)&_Iter->first, sizeof(KEY) }; }
								else { return { (uint8_t*)_Iter->first.Begin(), (uint32_t)_Iter->first.GetLength() }; }
							}
	virtual KVStoreValue	GetValue() override { return { (uint8_t*)_Iter->second.data(), (uint32_t)_Iter->second.size() }; }
	virtual void			Release() override { _SafeDel_ConstPtr(this); }
};

class KVStoreInMem: public itfc::KVStore
{
	os::CriticalSection					_CS;
	std::map<rt::String, std::string>	_Table;

	virtual int				GetPagedSize(){ return 0; }
	virtual int				GetPagedKeySize(){ return 0; }
	virtual void			Delete(const KVStoreKey* key){ EnterCSBlock(_CS); _Table.erase(rt::DS(key->Data, key->Size)); }
	virtual bool			Set(const KVStoreKey* key, const KVStoreValue* val){ EnterCSBlock(_CS); _Table[rt::DS(key->Data, key->Size)].assign((char*)val->Data, val->Size); return true; }
	virtual KVStoreValue	Get(const KVStoreKey* key, std::string* workspace)
							{	{	EnterCSBlock(_CS);
									auto it = _Table.find(rt::DS(key->Data, key->Size));
									if(it == _Table.end())return { nullptr, 0 };
									*workspace = it->second;
								}
								return { (uint8_t*)workspace->data(), (uint32_t)workspace->size() };
							}
	virtual bool			Has(const KVStoreKey* key){ EnterCSBlock(_CS); return _Table.find(rt::DS(key->Data, key->Size)) != _Table.end(); }

	virtual itfc::KVStoreIterator*	First() override { _CS.Lock(); return _New(KVStoreIterator<rt::String>(true, _CS, _Table)); }
	virtual itfc::KVStoreIterator*	Last() override { _CS.Lock(); return _New(KVStoreIterator<rt::String>(false, _CS, _Table)); }
	virtual itfc::KVStoreIterator*	Seek(const KVStoreKey* key) override { _CS.Lock(); return _New(KVStoreIterator<rt::String>(_CS, _Table, rt::String_Ref((char*)key->Data, key->Size))); }

	// paged only
	virtual KVStoreValue	GetPaged(const KVStoreKey* key, uint32_t page_no, std::string* workspace, uint32_t* total_size = nullptr) override { return {nullptr, 0}; }
	virtual	bool			SaveAllPages(const KVStoreKey* key, const KVStoreValue* value) override { return false; }
	virtual KVStoreValue	LoadAllPages(const KVStoreKey* key, std::string* value) override { return {nullptr, 0}; }
	virtual void			DeleteAllPages(const KVStoreKey* key) override {}
	virtual void			Release(){ _SafeDel_ConstPtr(this); }
};

class KVStorePagedInMem: public itfc::KVStore
{
	os::CriticalSection				_CS;
	std::map<GdpHash, std::string>	_Table;

	virtual int				GetPagedSize(){ return MRC_MEDIA_BLOB_PAGESIZE; }
	virtual int				GetPagedKeySize(){ return sizeof(GdpHash); }
	virtual void			Delete(const KVStoreKey* key){ ASSERT(0); }
	virtual bool			Set(const KVStoreKey* key, const KVStoreValue* val){ ASSERT(0); return false; }
	virtual KVStoreValue	Get(const KVStoreKey* key, std::string* workspace){ ASSERT(0); return { nullptr, 0 }; }

	virtual itfc::KVStoreIterator*	First() override { _CS.Lock(); return _New(KVStoreIterator<GdpHash>(true, _CS, _Table)); }
	virtual itfc::KVStoreIterator*	Last() override { _CS.Lock(); return _New(KVStoreIterator<GdpHash>(false, _CS, _Table)); }
	virtual itfc::KVStoreIterator*	Seek(const KVStoreKey* key) override { _CS.Lock(); return _New(KVStoreIterator<GdpHash>(_CS, _Table, *(GdpHash*)key->Data)); }

	virtual bool			Has(const KVStoreKey* key)
							{	ASSERT(key->Size == sizeof(GdpHash));
								EnterCSBlock(_CS);
								return _Table.find(*(GdpHash*)key->Data) != _Table.end();
							}
	virtual KVStoreValue	GetPaged(const KVStoreKey* key, uint32_t page_no, std::string* workspace, uint32_t* total_size = nullptr) override 
							{	ASSERT(key->Size == sizeof(GdpHash));
								uint32_t offset = page_no* MRC_MEDIA_BLOB_PAGESIZE;
								EnterCSBlock(_CS);
								auto it = _Table.find(*(GdpHash*)key->Data);
								if(it != _Table.end())
								{	uint32_t total = (uint32_t)it->second.size();
									if(offset < total)
									{	if(total_size)*total_size = total;
										total = rt::min(total - offset, MRC_MEDIA_BLOB_PAGESIZE);
										workspace->assign(it->second.data() + offset, total);
										return { (uint8_t*)workspace->data(), total };
									}
								}
								return { nullptr, 0 };
							}
	virtual	bool			SaveAllPages(const KVStoreKey* key, const KVStoreValue* value) override 
							{	ASSERT(key->Size == sizeof(GdpHash));
								EnterCSBlock(_CS);
								_Table[*(GdpHash*)key->Data].assign((char*)value->Data, value->Size);
								return true;
							}
	virtual KVStoreValue	LoadAllPages(const KVStoreKey* key, std::string* value) override
							{	ASSERT(key->Size == sizeof(GdpHash));
								EnterCSBlock(_CS);
								auto it = _Table.find(*(GdpHash*)key->Data);
								if(it != _Table.end())
								{	value->assign(it->second.data(), it->second.size());
									return { (uint8_t*)value->data(), (uint32_t)value->size() };
								}
								return { nullptr, 0 };
							}
	virtual void			DeleteAllPages(const KVStoreKey* key)
							{	ASSERT(key->Size == sizeof(GdpHash));
								EnterCSBlock(_CS);
								_Table.erase(*(GdpHash*)key->Data);
							}
	virtual void			Release(){ _SafeDel_ConstPtr(this); }
};

class InMemoryStorageFactory: public itfc::StorageFactory
{
	MrcMessageRelayStorage CreateMessageRelayStorage(const DhtAddress* swarm_addr, bool default_swarm) override
	{
		return {
			_New(KVStoreInMem),
			_New(KVStoreInMem)
		};
	}
	DvsKeyValueStorage CreateDistributedValueStorge(const DhtAddress* swarm_addr, bool default_swarm) override
	{
		return {
			_New(KVStorePagedInMem),
			_New(KVStoreInMem),
			_New(KVStoreInMem),
			_New(KVStoreInMem),

			_New(KVStoreInMem),
			_New(KVStoreInMem)
		};
	}
	MrcMediaRelayStorage CreateMediaRelayStorage() override
	{
		return {
			_New(KVStorePagedInMem),
			_New(KVStoreInMem),
			_New(KVStoreInMem),

			_New(KVStoreInMem),
			_New(KVStoreInMem)
		};
	}
	void Release(){ _SafeDel_ConstPtr(this); }
};

} // namespace _impl

itfc::StorageFactory*	AllocateMemoryStorageFactory(){ return _New(_impl::InMemoryStorageFactory); }
itfc::KVStore*			AllocateMemoryKVStore(){ return _New(_impl::KVStoreInMem); }
itfc::KVStore*			AllocateMemoryKVStorePaged(){ return _New(_impl::KVStorePagedInMem); }

};