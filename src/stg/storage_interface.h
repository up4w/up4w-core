#pragma once
#include <string>
#include "../net_types.h"


namespace upw
{

namespace itfc
{
struct KVStore;

//////////////////////////////////////////////////////
// Stores per module
struct MrcMessageRelayStorage
{
	KVStore*	pPackets;
	KVStore*	pTimeHashIndex;
};

struct MrcMediaRelayStorage
{
	KVStore*	pBlobs;		// paged
	KVStore*	pOffloads;
	KVStore*	pBlobTimeHashIndex;
	KVStore*	pLocalBlobs;
	KVStore*	pKeySwarmMap;
};

struct DvsKeyValueStorage
{
	KVStore*	pKeyValues; // paged
	KVStore*	pPendingPoW;
	KVStore*	pMaintainedKeys;
	KVStore*	pKeyValueMetadata;
	KVStore*	pCachedKeyValues;
	KVStore*	pCachedKeyValueMetadata;
};

//////////////////////////////////////////////////////
// TableStore Interface
struct KVStoreKey
{
	const uint8_t*	Data;
	uint32_t		Size;
};
typedef KVStoreKey KVStoreValue;

struct KVStoreIterator
{
	virtual bool			IsValid() = 0;
	virtual void			Next() = 0;
	virtual void			Prev() = 0;
	virtual KVStoreKey		GetKey() = 0;
	virtual KVStoreValue	GetValue() = 0;
	virtual void			Release() = 0;
};

struct KVStore
{
	// both non-paged and paged
	virtual int					GetPagedSize() = 0; // return 0 for non-paged
	virtual int					GetPagedKeySize() = 0; // return 0 for non-paged
	virtual void				Delete(const KVStoreKey* key) = 0;
	// non-paged only
	virtual bool				Set(const KVStoreKey* key, const KVStoreValue* val) = 0;
	virtual KVStoreValue		Get(const KVStoreKey* key, std::string* workspace) = 0;
	virtual bool				Has(const KVStoreKey* key) = 0;
	virtual KVStoreIterator*	First() = 0;
	virtual KVStoreIterator*	Last() = 0;
	virtual KVStoreIterator*	Seek(const KVStoreKey* key) = 0;

	// paged only
	virtual KVStoreValue		GetPaged(const KVStoreKey* key, uint32_t page_no, std::string* workspace, uint32_t* total_size = nullptr)  = 0;
	virtual	bool				SaveAllPages(const KVStoreKey* key, const KVStoreValue* value) = 0;
	virtual KVStoreValue		LoadAllPages(const KVStoreKey* key, std::string* value) = 0;
	virtual void				DeleteAllPages(const KVStoreKey* key) = 0;
	virtual void				Release() = 0;
};

struct StorageFactory
{
	virtual	MrcMessageRelayStorage		CreateMessageRelayStorage(const DhtAddress* swarm_addr, bool default_swarm) = 0;
	virtual DvsKeyValueStorage			CreateDistributedValueStorge(const DhtAddress* swarm_addr, bool default_swarm) = 0;
	virtual MrcMediaRelayStorage		CreateMediaRelayStorage() = 0;
	virtual void						Release() = 0;
};

} // namespace itfc

///////////////////////////////////////////////////////////////////////
// Wrapper Classes
typedef itfc::MrcMediaRelayStorage		MrcMediaRelayStorage;
typedef itfc::MrcMessageRelayStorage	MrcMessageRelayStorage;
typedef itfc::DvsKeyValueStorage		DvsKeyValueStorage;
typedef itfc::StorageFactory			StorageFactory;
typedef itfc::KVStoreKey				KVStoreKey;
typedef itfc::KVStoreValue				KVStoreValue;

class KVStoreData: public itfc::KVStoreKey
{
protected:
	uint8_t	_embedded[8];
public:
	KVStoreData():KVStoreKey{nullptr, 0}{}
	KVStoreData(LPCVOID p, uint32_t sz):KVStoreKey{(uint8_t*)p, sz}{}

	KVStoreData(int i):KVStoreKey{_embedded, sizeof(i)}{ *((int*)_embedded) = i; }
	KVStoreData(BYTE i):KVStoreKey{_embedded, sizeof(i)}{ *((BYTE*)_embedded) = i; }
	KVStoreData(WORD i):KVStoreKey{_embedded, sizeof(i)}{ *((WORD*)_embedded) = i; }
	KVStoreData(DWORD i):KVStoreKey{_embedded, sizeof(i)}{ *((DWORD*)_embedded) = i; }
	KVStoreData(ULONGLONG i):KVStoreKey{_embedded, sizeof(i)}{ *((ULONGLONG*)_embedded) = i; }
	KVStoreData(LONGLONG i):KVStoreKey{_embedded, sizeof(i)}{ *((LONGLONG*)_embedded) = i; }
	KVStoreData(float i):KVStoreKey{_embedded, sizeof(i)}{ *((float*)_embedded) = i; }
	KVStoreData(double i):KVStoreKey{_embedded, sizeof(i)}{ *((double*)_embedded) = i; }

	KVStoreData(LPSTR str):KVStoreKey{(uint8_t*)str, str?(uint32_t)strlen(str):0}{}
	KVStoreData(LPCSTR str):KVStoreKey{(uint8_t*)str, str?(uint32_t)strlen(str):0}{}
	KVStoreData(const KVStoreKey& i):KVStoreKey(i){}

	template<typename T>
	KVStoreData(const T& x)
		:KVStoreKey{(uint8_t*)rt::GetDataPtr(x), (uint32_t)rt::GetDataSize(x)}
	{}

	SIZE_T GetSize() const { return Size; }

	rt::String_Ref ToString(SIZE_T off = 0) const { ASSERT(Size>=off); return rt::String_Ref((LPCSTR)Data + off, Size - off); }
	template<typename T>
	const T& To(SIZE_T off = 0) const {	ASSERT(Size >= off + sizeof(T)); return *((T*)(Data + off)); }
};

class KVStoreIterator
{
	itfc::KVStoreIterator*Iter = nullptr;
public:
	bool				IsValid() const { return Iter && Iter->IsValid(); }
	void				Next(){ Iter->Next(); }
	void				Prev(){ Iter->Prev(); }
	itfc::KVStoreKey	GetKey() const { return Iter->GetKey(); }
	itfc::KVStoreValue	GetValue() const { return Iter->GetValue(); }

	template<typename T>
	const T&			Key() const { return static_cast<KVStoreData&&>(GetKey()).To<T>(); }
	template<typename T>
	const T&			Value() const { return static_cast<KVStoreData&&>(GetValue()).To<T>(); }

	KVStoreIterator() = default;
	~KVStoreIterator(){ _SafeRelease(Iter); }
	KVStoreIterator(const KVStoreIterator& x) = delete;
	KVStoreIterator(KVStoreIterator&& x){ Iter = x.Iter; x.Iter = nullptr; }
	KVStoreIterator(itfc::KVStoreIterator* x){ Iter = x; }
};

class KVStore
{
	itfc::KVStore*		DB = nullptr;
public:
	void				Delete(const KVStoreData& key){ DB->Delete(&key); }
	bool				Set(const KVStoreData& key, const KVStoreData& val){ return DB->Set(&key, &val); }
	itfc::KVStoreValue	Get(const KVStoreData& key, std::string* workspace){ return DB->Get(&key, workspace); }
	bool				Has(const KVStoreData& key){ return DB->Has(&key); }
	KVStoreIterator		First(){ return DB->First(); }
	KVStoreIterator		Last(){ return DB->Last(); }
	KVStoreIterator		Seek(const KVStoreData& key){ return DB->Seek(&key); }

	itfc::KVStoreValue	GetPaged(const KVStoreData& key, uint32_t page_no, std::string* workspace, uint32_t* total_size = nullptr){ return DB->GetPaged(&key, page_no, workspace, total_size); }
	itfc::KVStoreValue	LoadAllPages(const KVStoreData& key, std::string* page){ return DB->LoadAllPages(&key, page); }
	bool				SaveAllPages(const KVStoreData& key, const KVStoreData& val){ return DB->SaveAllPages(&key, &val); } 
	void				DeleteAllPages(const KVStoreData& key){ DB->DeleteAllPages(&key); }
	
	void operator = (itfc::KVStore* x){ _SafeRelease(DB); DB = x; }
	bool IsEmpty() const { return DB == nullptr; }
	void Empty(){ _SafeRelease(DB); }

	KVStore() = default;
	~KVStore(){ Empty(); }

	template<typename t_POD>
	bool GetAs(const KVStoreData& k, t_POD* valout) const
	{	ASSERT_NO_FUNCTION_REENTRY;
		static_assert(rt::TypeTraits<t_POD>::IsPOD);
		thread_local std::string temp;
		auto ret = DB->Get(&k, &temp);
		if(ret.Size == sizeof(t_POD))
		{	memcpy(valout, ret.Data, sizeof(t_POD));
			return true;
		}else return false;
	}
	bool Get(const KVStoreData& key, std::string& out){ return DB->Get(&key, &out).Data; }
};

extern itfc::StorageFactory*	AllocateMemoryStorageFactory();
extern itfc::KVStore*			AllocateMemoryKVStore();
extern itfc::KVStore*			AllocateMemoryKVStorePaged();

} // namespace upw
