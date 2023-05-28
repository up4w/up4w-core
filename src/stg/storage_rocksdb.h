#pragma once
#include "../../externs/miniposix/core/ext/rocksdb/rocksdb.h"
#include "storage_interface.h"
#include "../gdp/gdp_base.h"
#include "../mrc/mrc_base.h"


namespace upw
{
namespace _impl
{

class UnifiedStorageFactory;

struct RocksIterator: public upw::itfc::KVStoreIterator
{
	ext::RocksCursor Iter;

	virtual bool					IsValid() override { return !Iter.IsEmpty() && Iter.IsValid(); }
	virtual void					Next() override { Iter.Next(); }
	virtual void					Prev() override { Iter.Prev(); }
	virtual upw::KVStoreKey			GetKey() override { auto k = Iter.Key(); return { (uint8_t*)k.data_, (uint32_t)k.size_ }; }
	virtual upw::KVStoreValue		GetValue() override { auto v = Iter.Value(); return { (uint8_t*)v.data_, (uint32_t)v.size_ }; }
	virtual void					Release() override { _SafeDel_ConstPtr(this); }

	RocksIterator(ext::RocksCursor&& x){ rt::Swap(Iter, x); }
};

struct RocksStore: public upw::itfc::KVStore
{
	UnifiedStorageFactory*	_pFactory;
	ext::RocksDB	DB;
	RocksStore(ext::RocksDB::_RocksDBIntl&& x, UnifiedStorageFactory* f = nullptr):DB(x), _pFactory(f){}
	~RocksStore();

	virtual int							GetPagedSize() override { return 0; }
	virtual int							GetPagedKeySize() override { return 0; }
	virtual void						Delete(const upw::KVStoreKey* key) override { DB.Delete(::ext::SliceValue(key->Data, key->Size)); }
	virtual bool						Set(const upw::KVStoreKey* key, const upw::KVStoreValue* val) override { return DB.Set(ext::SliceValue(key->Data, key->Size), ext::SliceValue(val->Data, val->Size)); }
	virtual upw::KVStoreValue			Get(const upw::KVStoreKey* key, std::string* ws) override { if(DB.Get(::ext::SliceValue(key->Data, key->Size), *ws))return {(uint8_t*)ws->data(), (uint32_t)ws->size()};else return {nullptr,0}; }
	virtual bool						Has(const upw::KVStoreKey* key) override { return DB.Has(ext::SliceValue(key->Data, key->Size)); }
	virtual upw::itfc::KVStoreIterator*	First() override { return _New(RocksIterator(DB.First())); }
	virtual upw::itfc::KVStoreIterator*	Last() override { return _New(RocksIterator(DB.Last())); }
	virtual upw::itfc::KVStoreIterator*	Seek(const upw::KVStoreKey* key) override { return _New(RocksIterator(DB.Seek(ext::SliceValue(key->Data, key->Size)))); }
	virtual void						Release(){ _SafeDel_ConstPtr(this); }

	// paged only
	virtual upw::KVStoreValue			GetPaged(const upw::KVStoreKey* key, uint32_t page_no, std::string* workspace, uint32_t* total_size = nullptr) override { return {nullptr, 0}; }
	virtual	bool						SaveAllPages(const upw::KVStoreKey* key, const upw::KVStoreValue* value) override { return false; }
	virtual upw::KVStoreValue			LoadAllPages(const upw::KVStoreKey* key, std::string* value) override { return {nullptr, 0}; }
	virtual void						DeleteAllPages(const upw::KVStoreKey* key) override {}
};

struct RocksStorePaged: public upw::itfc::KVStore
{
	UnifiedStorageFactory*	_pFactory;
	ext::RocksDBPaged<GdpHash, void, MRC_MEDIA_BLOB_PAGESIZE>	DB;
	RocksStorePaged(ext::RocksDB::_RocksDBIntl&& x, UnifiedStorageFactory* f = nullptr):DB(x), _pFactory(f){}
	~RocksStorePaged();

	virtual void						Delete(const upw::KVStoreKey* key) override { ASSERT(0); }
	virtual bool						Set(const upw::KVStoreKey* key, const upw::KVStoreValue* val) override { ASSERT(0); return false; }
	virtual upw::KVStoreValue			Get(const upw::KVStoreKey* key, std::string* ws) override { ASSERT(0); return { nullptr, 0 }; }

	virtual void						Release(){ _SafeDel_ConstPtr(this); }
	virtual int							GetPagedSize() override { return MRC_MEDIA_BLOB_PAGESIZE; }
	virtual int							GetPagedKeySize() override { return sizeof(GdpHash); }
	virtual upw::itfc::KVStoreIterator*	First() override { return _New(RocksIterator(DB.First())); }
	virtual upw::itfc::KVStoreIterator*	Last() override { return _New(RocksIterator(DB.Last())); }
	virtual upw::itfc::KVStoreIterator*	Seek(const upw::KVStoreKey* key) override { ASSERT(key->Size == sizeof(GdpHash)); return _New(RocksIterator(DB.Seek(ext::SliceValue(key->Data, key->Size)))); }
	virtual bool						Has(const upw::KVStoreKey* key) override { ASSERT(key->Size == sizeof(GdpHash)); return DB.Has(ext::SliceValue(key->Data, key->Size)); }
	virtual upw::KVStoreValue			GetPaged(const upw::KVStoreKey* key, uint32_t page_no, std::string* workspace, uint32_t* total_size = nullptr) override;
	virtual	bool						SaveAllPages(const upw::KVStoreKey* key, const upw::KVStoreValue* value) override;
	virtual upw::KVStoreValue			LoadAllPages(const upw::KVStoreKey* key, std::string* value) override;
	virtual void						DeleteAllPages(const upw::KVStoreKey* key) override;
};

} // namespace _impl

enum class RocksMergeMode
{
	__Undefined = -1,
	Separated = 0,
	Dedicated, // two storage, one for default swarm, another for all non-default ones
	All
};

extern itfc::StorageFactory* AllocateUnifiedStorageFactory(
	const rt::String_Ref& mrc_dir, RocksMergeMode mrc_db_mode = RocksMergeMode::Separated, const rt::String_Ref& mds_dir = nullptr,
	const rt::String_Ref& kvs_dir = nullptr, RocksMergeMode kvs_db_mode = RocksMergeMode::Separated
);

} // namespace upw