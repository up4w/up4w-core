#include "../netsvc_core.h"
#include "../swarm_broadcast.h"
#include "mrc_message.h"
#include "mrc_swarm.h"


namespace upw
{

namespace _details
{
	const UINT _MRC_LOSS_RATE_ = 0; //only for test
	const MrcMsgHash MRC_ROOT = 0;
	const NetworkAddress EMPTY_ADDR(ext::CTOR_ZERO);

	enum MRC_LOG_STATUS
	{
		DLS_OFF = 0,
		DLS_ON = 1,

		DLS_LOG = 1,
		DLS_TRACE = 2,
	};
	MRC_LOG_STATUS _MRC_LOG_STATUS_ = DLS_TRACE;

	struct AtomicCounter
	{
		volatile int64_t* _Addr;
		AtomicCounter(volatile int64_t* p) : _Addr(p) { os::AtomicIncrement(_Addr); }
		~AtomicCounter() { os::AtomicDecrement(_Addr); }
	};
}

#if defined(PLATFORM_RELEASE_BUILD) || defined(PLATFORM_SUPPRESS_DEBUG_LOG)
#define MRC_LOG(X) {}
#define MRC_TRACE(X) {}
#else
#define MRC_LOG(X) if(_details::_MRC_LOG_STATUS_ >= _details::DLS_LOG) _LOGC("[DAG]: " << os::Timestamp::Get() << ": " << X)
#define MRC_TRACE(X) if(_details::_MRC_LOG_STATUS_ >= _details::DLS_TRACE) _LOGC("[DAG]: " << os::Timestamp::Get() << ": " << X)
#endif

bool MrcMessageRelayStore::Init(const MrcMessageRelayStorage& store)
{
	EnterCSBlock(_StoreCS);

	ASSERT(_Packets.IsEmpty() && _TimeHashIndex.IsEmpty());
	
	_Packets = store.pPackets; // db.Get(pDAGTableName);
	_TimeHashIndex = store.pTimeHashIndex; // db.Get(pDAGIndexName);

	if(!_Packets.IsEmpty() && !_TimeHashIndex.IsEmpty())
	{
		//SummaryRocksDB(_Packets,"MrcMessageRelayStore::_Packets");
		//SummaryRocksDB(_TimeHashIndex, "MrcMessageRelayStore::_TimeHashIndex");
		{
			for(auto it = std::move(_TimeHashIndex.First()); it.IsValid(); it.Next())
				os::AtomicIncrement(&_Status.MRC_COUNT);
		}

		_Opened = true;
		_StopSearch = false;
		return true;
	}

	Term();
	return false;
}

void MrcMessageRelayStore::Term()
{
	StopSearch();

	EnterCSBlock(_StoreCS);

	_Opened = false;

	_Packets.Empty();
	_TimeHashIndex.Empty();
}

#define AutoCounter(v) _details::AtomicCounter MARCO_JOIN(_Auto_counter_,__COUNTER__)(&v)

void MrcMessageRelayStore::Search(int64_t from, int64_t to, const ext::fast_set<MrcContactPointNum>* cps_ptr, std::function<void(const MrcMessage& packet)> callback)
{
	EnterCSBlock(_StoreCS);
	if (!_Opened)
		return;

	MRC_TRACE("Search from:" << from);

	AutoCounter(_SearchCount);
	auto it = _TimeHashIndex.Seek(TimeDAGHashKey{(LONGLONG)from, {}});
	while(!_StopSearch && it.IsValid())
	{
		auto& key = it.Key<TimeDAGHashKey>();
		if(key.Time > to)
			break;

		auto* packet = Get(key.Hash, true);

		if(packet && callback)
		{
			if(!cps_ptr || packet->GetEnvelope().MatchContactPoint(*cps_ptr))
				callback(*packet);
		}

		it.Next();
	}
}

void MrcMessageRelayStore::StopSearch()
{
	_StopSearch = true;
	while (_SearchCount) os::Sleep(100);
	_StopSearch = false;
}


void MrcMessageRelayStore::Thrink()
{
	EnterCSBlock(_StoreCS);
	if(!_Opened)
		return;

	MRC_TRACE("Now:" << _Status.NOW);
	{
		MRC_TRACE("Thrink DB to:" << _Status.DB_StoreFrom);
		int count = 0;
		auto it = _TimeHashIndex.First();
		while(it.IsValid() && it.Key<TimeDAGHashKey>().Time < _Status.DB_StoreFrom)
		{
			if(it.GetValue().Size == sizeof(int64_t))
			{
				int64_t exp = it.Value<int64_t>();
				if(exp > _Status.NOW) 
				{
					it.Next();
					continue;
				}
			}

			count++;
			auto key = it.Key<TimeDAGHashKey>();

			it.Next();

			_Packets.Delete(key.Hash);
			_TimeHashIndex.Delete(key);
			_UnReferred.erase(key.Hash);
			_UnconfirmedSet.erase(key.Hash);
			os::AtomicDecrement(&_Status.MRC_COUNT);
			
		}
		MRC_TRACE("Thrink DB count:" << count);

		count = 0;
		while(it.IsValid())
		{
			count++;
			it.Next();
		}
		MRC_TRACE("Exist in DB count:" << count);
	}

	{
		MRC_TRACE("Thrink Mem to:" << _Status.MEM_StoreFrom);
		int count = 0;

		for (auto it = _DAGTimeHashIndex.begin(); it!= _DAGTimeHashIndex.end();)
		{
			if (it->first < _Status.MEM_StoreFrom)
			{
				count++;
				MrcMsgHash& hash = it->second;
				auto it_2 = _DAGPackets.find(hash);
				if (it_2 != _DAGPackets.end())
				{
					_SafeFree32AL(it_2->second);
					_DAGPackets.erase(hash);
				}

				_LostSet.erase(hash);
				_Referred.erase(hash);
				_DAGTimeHashIndex.erase(it++);
			}
			else
			{
				break;
			}
		}
		MRC_TRACE("Thrink Mem count:" << count);
	}

	{
		rt::String s;
		Dump(s);
		MRC_TRACE("DAG Status:\r\n" << s);
	}
}

void MrcMessageRelayStore::_PutInMem(MrcMsgHash hash, MrcMessage* packet)
{
	_DAGPackets[hash] = packet;
	_DAGTimeHashIndex.insert({ packet->GetTime(), hash });
}

const MrcDagStatus* MrcMessageRelayStore::BuildStatus(rt::BufferEx<BYTE>& buf)
{
	MrcDagStatus* local_status = nullptr;

	{
		EnterCSBlock(_StoreCS);
		if(!_Opened) 
			return nullptr;

		int ct = (int)_UnReferred.size();
		if(ct > MRC_STATUS_PING_MAX_COUNT)
			ct = MRC_STATUS_PING_MAX_COUNT;
		int sz = offsetof(MrcDagStatus, Heads) + ct * sizeof(MrcMsgHash);
		buf.SetSize(sz);
		local_status = (MrcDagStatus*)((LPBYTE)buf.Begin());
		local_status->Count = 0;

		for(auto& hash : _UnReferred)
		{
			local_status->Heads[local_status->Count++] = hash;
			if(local_status->Count >= ct)
				break;
		}
	}
	
	return local_status;
}


void MrcMessageRelayStore::SearchMissing(const MrcDagStatus& remote_status, std::function<void(MrcMsgHash hash)> callback)
{
	EnterCSBlock(_StoreCS);
	if(!_Opened)
		return;

	// find which MrcMsgHash is not exist in local

	for(BYTE i = 0; i < remote_status.Count; i++)
	{
		auto& hash = remote_status.Heads[i];

		if(!_Has(hash))
		{
			callback(hash);
		}
	}
}

bool MrcMessageRelayStore::_Has(MrcMsgHash hash)
{
	if(_DAGPackets.count(hash) > 0)
		return true;

	if(_Packets.Has(hash))
		return true;
	
	return false;
}

MrcMessage* MrcMessageRelayStore::Put(MrcMsgHash hash, const MrcMessage& packet, PacketSource source)
{
	EnterCSBlock(_StoreCS);
	if(!_Opened)
		return nullptr;

	if(0)
	{
		rt::String_Ref raw((char*)&packet, packet.GetSize());
		rt::String out;
		os::Base64Encode(raw, out);
		_LOG("MRC_BASE64: " << out);
	}

	if(_Has(hash)) // exist?
	{
		MRC_TRACE("exist, drop:" << hash);
		return nullptr;
	}
	else
	{
		os::AtomicIncrement(&_Status.MRC_COUNT);
	}

	rt::String s;
	packet.Dump(s, (MrcMsgHash*)&hash);
	MRC_TRACE("recv msg, " << s);

	// clone it from network buffer
	MrcMessage* mem = MrcMessage::Clone(packet);

	
	if(!mem)
		return nullptr;
		
	_PutInMem(hash, mem);

	if(source == PKSRC_LOCALHOST)
	{
		MRC_TRACE(" UnconfirmedSet add : " << s);
		_UnconfirmedSet.insert(hash);
	}
	
	if(source!=PKSRC_DATABASE)
	{
		_Packets.Set(hash, KVStoreData(&packet, packet.GetSize()));

        TimeDAGHashKey key ={(LONGLONG)mem->GetTime(), hash};
		_TimeHashIndex.Set(key, packet.GetExpirationTime());
	}
	
	// remove from lost & missing
	auto in_lost = _LostSet.erase(hash);
	auto in_missing = _MissingMap.erase(hash);
	_Status.MRC_MISSING = _MissingMap.size();
	auto in_Referred = _Referred.count(hash);

	// if it is new, save it in unreferred
	if( !in_lost && !in_missing && !in_Referred)
	{
		_UnReferred.insert(hash);
		_Status.MRC_UNREFERRED = _UnReferred.size();
	}

	// check parents status
	for(UINT i = 0; i < mem->GetParentCount(); i++)
	{
		auto& parent_hash = mem->Parents[i];

		if(parent_hash == _details::MRC_ROOT)
			continue;

		_UnconfirmedSet.erase(parent_hash);

		// remove parent from unreferred
		_UnReferred.erase(parent_hash);
		_Status.MRC_UNREFERRED = _UnReferred.size();

		// save parent in referred
		_Referred.insert(parent_hash);

		// packet is timeout
		if(packet.GetEnvelope().Time < _Status.DB_StoreFrom)
			continue;

		// parent exist
		if(_Has(parent_hash))
			continue;
			
		// try to find parent
		_MissingMap[parent_hash] = MissingRecord(packet.GetTime(), 0);
		_Status.MRC_MISSING = _MissingMap.size();
		MRC_TRACE("add Missing:" << parent_hash);

		// only request from network 
		if(source != PKSRC_DATABASE)
		{
			_Func_Callback_Missing(parent_hash);
		}

	}

	return mem;	
}

void MrcMessageRelayStore::SearchUnconfirmed(std::function<void(const MrcMessage& packet)> callback)
{
	EnterCSBlock(_StoreCS);
	if(!_Opened)
		return;

	int ct = 0;
	for(auto hash : _UnconfirmedSet)
	{
		auto it = _DAGPackets.find( hash );
		if(it != _DAGPackets.end())
		{
			ct++;
			callback(*(it->second));
		}
	}

	if(ct)
	{
		MRC_TRACE("Broadcast Unconfirmed Dag Message : "<<ct);
	}
}

void MrcMessageRelayStore::SearchMissing(std::function<void(MrcMsgHash)> callback)
{
	EnterCSBlock(_StoreCS);
	if(!_Opened)
		return;

	for(auto it = _MissingMap.begin(); it != _MissingMap.end();)
	{
		auto& tm = it->second;
		if(tm.ReferTime < _Status.DB_StoreFrom || tm.RequestCount>10)
		{
			_LostSet.insert(it->first);
			_MissingMap.erase(it++);
			_Status.MRC_MISSING = _MissingMap.size();
		}
		else
		{
			if(_Status.NOW - tm.RequestLastTime > 5000)
			{
				MRC_TRACE("Refer : " << tm.ReferTime);
				callback(it->first);
				tm.RequestLastTime = _Status.NOW;
				tm.RequestCount++;
			}
			it++;
		}
	}
	
}

MrcMessageRelayStore::MrcMessageRelayStore(std::function<void(MrcMsgHash)>func_callback_missing)
	:_Func_Callback_Missing(func_callback_missing)
{
}

int MrcMessageRelayStore::PickParents(MrcMsgHash hash[MRC_PACKETS_PARENT_COUNT])
{
	EnterCSBlock(_StoreCS);
	if(!_Opened)
		return 0;

	int max = 2;
	int nc = (int)_UnReferred.size();
	if(nc > MRC_MESSAGE_PARENT_FULL_COUNT)
		max = 4;
	else if(nc > MRC_MESSAGE_PARENT_HALF_COUNT)
		max = 3;

	if(max > MRC_PACKETS_PARENT_COUNT) max = MRC_PACKETS_PARENT_COUNT;

	int r = 0;

	// seek in  unreferred
	{
		auto it = _UnReferred.begin();
		while(it != _UnReferred.end())
		{
			hash[r++] = *it;
			_UnReferred.erase(it++);

			if(r >= max)
				return r;
		}
	}

	if(r > 0)
		return r;

	// no data exist
	hash[0] = _details::MRC_ROOT;
	return 1;
}

const MrcMessage* MrcMessageRelayStore::Get(MrcMsgHash hash, bool cache_in_mem)
{
	thread_local static std::string __rocksdb_buf;

	EnterCSBlock(_StoreCS);

	if(!_Opened)
		return nullptr;

	auto it = _DAGPackets.find(hash);
	if(it != _DAGPackets.end())
		return it->second;

	{	// load from db
		if(_Packets.Get(hash, __rocksdb_buf))
		{
			MrcMessage* packet = (MrcMessage*)__rocksdb_buf.data();

			if(!packet->IsValidSize((int)__rocksdb_buf.size()) || !packet->IsValidPow())
			{
				MRC_TRACE("[MrcMessageRelayStore::Get] Recv Error Fromat Data, Drop it !");
				return nullptr;
			}

			if(_bCacheDBResult || cache_in_mem)
			{
				Put(hash, *packet, PKSRC_DATABASE);
			}
			return (MrcMessage*)__rocksdb_buf.data();
		}
	}
		
	return nullptr;
}

void MrcMessageRelayStore::Dump(rt::String out, bool show_detail)
{
	EnterCSBlock(_StoreCS);

	struct TimeDAGHash
	{
		int64_t			Time;
		MrcMsgHash	Hash;
		bool operator <(const TimeDAGHash& rhs) const {	return Time < rhs.Time;	}
		TimeDAGHash(int64_t time, MrcMsgHash hash)
			: Time(time) , Hash(hash)
		{}
	};

	std::vector<MrcMsgHash> vec;
	rt::String s;

	if(show_detail)
	{
		{
			std::vector<TimeDAGHash> vec;
			for(auto& it : _DAGPackets)
				vec.push_back(TimeDAGHash(it.second->GetTime(), it.first));

			std::sort(vec.begin(), vec.end());

			_LOGC("[Exist]");
			for(auto& key : vec)
			{
				_DAGPackets[key.Hash]->Dump(s);
				_LOGC(key.Time << " " << s);
			}
		}

		vec.clear();
		{
			for(auto& it : _MissingMap)
				vec.push_back(it.first);

			std::sort(vec.begin(), vec.end());

			_LOGC("[Missing]");
			for(auto& hash : vec)
				_LOGC(hash);
		}

		vec.clear();
		{
			for(auto& it : _LostSet)
				vec.push_back(it);

			std::sort(vec.begin(), vec.end());

			_LOGC("[Lost]");
			for(auto& hash : vec)
				_LOGC(hash);
		}

		vec.clear();
		{
			for(auto& it : _UnReferred)
				vec.push_back(it);

			std::sort(vec.begin(), vec.end());

			_LOGC("[ChildlessSet]");
			for(auto& hash : vec)
			{
				auto it = _DAGPackets.find(hash);
				if(it == _DAGPackets.end())
				{
					_LOGC("Removed:" << hash);
					_UnconfirmedSet.erase(hash);
				}
				else
				{
					it->second->Dump(s);
					_LOGC(s);
				}

			}
		}

		vec.clear();
		{
			for(auto& it : _UnconfirmedSet)
				vec.push_back(it);

			std::sort(vec.begin(), vec.end());

			_LOGC("[Unconfirmed]");
			for(auto& hash : vec)
			{
				auto it = _DAGPackets.find(hash);
				if(it == _DAGPackets.end())
				{
					_LOGC("Removed:" << hash);
					_UnconfirmedSet.erase(hash);
				}
				else
				{
					it->second->Dump(s);
					_LOGC(s);
				}

			}
		}
	}

	MRC_LOG("Exist      : " << _DAGPackets.size());
	MRC_LOG("Missing    : " << _MissingMap.size());
	MRC_LOG("Lost       : " << _LostSet.size());
	MRC_LOG("Childless  : " << _UnReferred.size());
	MRC_LOG("UnConfirmed: " << _UnconfirmedSet.size());
}

MrcWorkload MrcMessageRelayStore::GetWorkload()
{
	return { _Status.MRC_COUNT, _Status.MRC_UNREFERRED, _Status.MRC_MISSING };
}

void MrcMessageRelayStore::GetPooled(Void_Func_With_MrcMessage cb, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit)
{
#define filter_match(e) ((!app||app==e.App) && (!action||action==e.Action))

	EnterCSBlock(_StoreCS);

	if (_DAGTimeHashIndex.size() == 0)
		return;

	uint16_t count = 0;

	if (from <= to)
	{
		auto it = _DAGTimeHashIndex.lower_bound(from);
		while (count < limit && it != _DAGTimeHashIndex.end() && it->first <= to)
		{
			auto it2 = _DAGPackets.find(it->second);
			if (it2 != _DAGPackets.end())
			{
				auto* msg = it2->second;
				auto& e = msg->GetEnvelope();
				if (filter_match(e))
				{
					count++;
					cb(*msg);
				}
			}
			it++;
		}
	}
	else
	{
		auto it = _DAGTimeHashIndex.lower_bound(from);
		if (it == _DAGTimeHashIndex.end())
			it--;

		if (it->first > from)
			return;

		while (count < limit && it != _DAGTimeHashIndex.end() && it->first >= to)
		{
			auto it2 = _DAGPackets.find(it->second);
			if (it2 != _DAGPackets.end())
			{
				auto* msg = it2->second;
				auto& e = msg->GetEnvelope();
				if (filter_match(e))
				{
					count++;
					cb(*msg);
				}
			}
			it--;
		}
	}

#undef filter_match

}

int64_t MrcMessageRelayStore::GetMissingTime(int64_t from)
{
	EnterCSBlock(_StoreCS);
	int64_t find = 0;
	int64_t tm;

	for(auto &it : _MissingMap)
	{
		tm = it.second.ReferTime;
		if(tm<from && tm>find)
			find = tm;
	}

	return find;
}

namespace _details
{
struct MrcFragmentAssembler
{
	static const uint32_t FRAGMENT_SIZE = 1024;
	static const uint32_t SIZE_EDGE		= 1400;
	typedef	DWORD FRAGMENT_ID;
	struct Fragment
	{
		FRAGMENT_ID	Id;
		BYTE			Count;
		WORD			LastSize;
		BYTE			SN;
		BYTE			Data[1];
	};
	struct JointFragments
	{
		int64_t			CreateTime;
		FRAGMENT_ID	Id;
		BYTE			Count;
		WORD			LastSize;
		BYTE			Bitmap[256 / 8];
		BYTE			Filled;
		BYTE			Data[1];

		uint32_t GetDataSize() { return FRAGMENT_SIZE * (Count - 1) + LastSize; }
		static JointFragments* Alloc(FRAGMENT_ID id, BYTE count, WORD lastsize)
		{
			auto* p = (JointFragments*)_Malloc32AL(BYTE, offsetof(JointFragments, Data) + FRAGMENT_SIZE * count);
			if(p)
			{
				p->CreateTime = os::Timestamp::Get();
				p->Id = id;
				p->Count = count;
				p->LastSize = lastsize;
				rt::Zero(p->Bitmap, sizeof(p->Bitmap));
				p->Filled = 0;
			}
			return p;
		}
		static void Free(JointFragments* p){ _SafeFree32AL_ConstPtr(p);	}
	};
protected:
	os::CriticalSection	_StoreCS;
	rt::hash_map<FRAGMENT_ID, JointFragments*> _Store;
public:
	~MrcFragmentAssembler(){ Clear(); }
	void Clear()
	{
		EnterCSBlock(_StoreCS);
		for(auto it = _Store.begin(); it != _Store.end(); it++)
		{
			JointFragments::Free(it->second);
		}
		_Store.clear();
	}
	void Recycle()
	{
		EnterCSBlock(_StoreCS);
		int64_t gc_time = os::Timestamp::Get() - 10 * 1000;
		for(auto it = _Store.begin(); it != _Store.end(); )
		{
			if(it->second->CreateTime < gc_time)
			{
				JointFragments::Free(it->second);
				_Store.erase(it++);
			}
			else
				it++;
		}
	}

	JointFragments* Recv(void* ptr, int size)// if recv all fragments, return whole data (free needed); otherwise return nullptr
	{
		ASSERT(ptr);
		if(!ptr) return nullptr;
		Fragment* fragment = (Fragment*)ptr;
		int	data_size = size - offsetof(Fragment, Data);

		if(fragment->SN == fragment->Count - 1)
		{
			if(data_size > FRAGMENT_SIZE) return nullptr;
		}
		else if(fragment->SN < fragment->Count - 1)
		{
			if(data_size != FRAGMENT_SIZE) return nullptr;
		}
		else
		{
			return nullptr;
		}

		EnterCSBlock(_StoreCS);
		JointFragments* joint = nullptr;
		auto it = _Store.find(fragment->Id);
		if(it != _Store.end())
			joint = it->second;
		else
		{
			joint = JointFragments::Alloc(fragment->Id, fragment->Count, fragment->LastSize);
			if(!joint) return nullptr;
			_Store[fragment->Id] = joint;
		}

		if(joint->Bitmap[fragment->SN / 8] & (1 << (fragment->SN % 8))) return nullptr;

		if(fragment->SN == fragment->Count - 1)
		{
			if(data_size != fragment->LastSize) return nullptr;
		}

		joint->Bitmap[fragment->SN / 8] |= (1 << (fragment->SN % 8));
		memcpy(&joint->Data[fragment->SN * FRAGMENT_SIZE], &fragment->Data[0], data_size);
		joint->Filled++;

		if(joint->Filled == joint->Count)
		{
			_Store.erase(fragment->Id);
			return joint;
		}

		return nullptr;
	}
};

struct NET_MRC_Fragment
{
	MrcHeader	Header;
	MrcFragmentAssembler::Fragment	Fragment;
};

int BuildMrcFragmentPacket(const Packet& source, const MrcFragmentAssembler::FRAGMENT_ID& id, int sn, PacketBuf<>& out) // 0: no more; -1: error; >0: more
{
	ASSERT(sn >= 0 && sn <= 256);
	if(sn < 0 || sn>256) return -1;

	const uint8_t* packet_data = (uint8_t*)source.GetData();
	const int   packet_length = source.GetLength();

	const int op_code = MrcHeader::CheckOpCode(packet_data);
	ASSERT(op_code == MrcHeader::OP_MESSAGE_CONTENT);
	if(op_code != MrcHeader::OP_MESSAGE_CONTENT) return -1;

	static const uint32_t MRC_FRAGMENT_SIZE = MrcFragmentAssembler::FRAGMENT_SIZE;
	int count = source.GetLength() / MRC_FRAGMENT_SIZE;
	int lastsize = source.GetLength() % MRC_FRAGMENT_SIZE;
	if(lastsize)
		count++;
	else
		lastsize = MRC_FRAGMENT_SIZE;

	if(sn >= count) return -1;

	int frag_data_size = (sn < count - 1) ? MRC_FRAGMENT_SIZE : lastsize;
	int buf_size = offsetof(NET_MRC_Fragment, Fragment.Data) + frag_data_size;
	out.Reset();
	NET_MRC_Fragment& net_fragmant = *(NET_MRC_Fragment*)out.Claim(buf_size);
	out.Commit(buf_size);
	net_fragmant.Header.Magic = MRC_PROTOCOL_CHAR_MAIN_SWARM;
	net_fragmant.Header.OpCode = MrcHeader::OP_FRAGMENT_DATA;
	net_fragmant.Fragment.Count = count;
	net_fragmant.Fragment.Id = id;
	net_fragmant.Fragment.LastSize = lastsize;
	net_fragmant.Fragment.SN = sn;
	memcpy(&net_fragmant.Fragment.Data[0], source.GetData() + sn * MRC_FRAGMENT_SIZE, frag_data_size);

	return count - sn - 1;
}

} // namespace _details

MrcMessageRelaySwarm::MrcMessageRelaySwarm(NetworkServiceCore* net, std::function<bool(const MrcMessage* data, MrcRecvContext& ctx)> func_callback_recvdata)
	: _pNetCore(net)
	, _Store(std::bind(&MrcMessageRelaySwarm::_Request, this, std::placeholders::_1, nullptr))
	, _OnMessageCallback(func_callback_recvdata)
{		
	_Fragments = new _details::MrcFragmentAssembler();
	rt::Randomizer(_status_r);
	for(int i = 0; i < 32; i++)
	{
		_uint_mask[i] = 1 << i;
	}

	_LOG("MrcMessageRelaySwarm Create Instance:" << rt::tos::HexNum<>(this));
}

MrcMessageRelaySwarm::~MrcMessageRelaySwarm()
{
	StopReplay();
	delete _Fragments;
	_LOG("MrcMessageRelaySwarm Destroy Instance:" << rt::tos::HexNum<>(this));
}

UINT MrcMessageRelaySwarm::_NetGetActiveDegree() const
{
	return _pNetCore->SMB().GetActiveDegree(_SwarmId);
}

bool MrcMessageRelaySwarm::Init(UINT swarm_id, StorageFactory* store_factory, bool default_swarm)
{
	ASSERT(swarm_id);
	SwarmAddress = *_pNetCore->SMB().GetAddressFromSwarmId(swarm_id);
	_pSwarmAddress = &SwarmAddress;
	_SwarmId = swarm_id;
	_bExtended = !default_swarm;

	_UpdateStoreTime();

	auto store = store_factory->CreateMessageRelayStorage(&SwarmAddress, default_swarm);
	if(store.pPackets && _Store.Init(store))
	{
		_UpdateStoreTime();

		// reload 
		_Store.Search(0, NetTimestamp::Max, nullptr, nullptr);

		return true;
	}

	Term();
	return false;
}

void MrcMessageRelaySwarm::Term()
{
	if(_bExtended)_pNetCore->SMB().Leave(_SwarmId);

	_Store.Term();
	_Fragments->Clear();
	_pSwarmAddress = nullptr;
}

void MrcMessageRelaySwarm::_UpdateStoreTime()
{
	int64_t t = _pNetCore->GetNetworkTime();

	_Store._Status.NOW = t;
	_Store._Status.TIME_Acceptable = t + MRC_PACKETS_MAX_TIMESHIFT;
	_Store._Status.DB_StoreFrom = t - MRC_PACKETS_DB_DURATION;
	_Store._Status.MEM_StoreFrom = t - MRC_PACKETS_MEM_DURATION;
}

void MrcMessageRelaySwarm::Replay(int64_t from, int64_t to, MrcRecvContext::SourceType source)
{
	_Store.Search(from, to, nullptr,
		[this, source](const MrcMessage& packet)
		{
			_OnRecvFromDB(packet, source);
		}
	);
}

void MrcMessageRelaySwarm::Replay(int64_t from, int64_t to, const ext::fast_set<MrcContactPointNum>& cps, MrcRecvContext::SourceType source)
{
	_Store.Search(from, to, &cps,
		[this, source](const MrcMessage& packet)
		{
			_OnRecvFromDB(packet, source);
		}
	);
}

void MrcMessageRelaySwarm::StopReplay()
{
	_Store.StopSearch();
}

//void MrcMessageRelaySwarm::Replay(osn_messages* messages, osn_recv_source source)
//{
//	_Store.Search(messages,
//		[this, source](const MrcMessage& packet)
//		{
//			_OnRecvFromDB(packet, source);
//		}
//	);
//}

void MrcMessageRelaySwarm::_OnRecvFromDB(const MrcMessage& packet, MrcRecvContext::SourceType source)
{
	auto hash = packet.GetHashValue();
	_Store.Put(hash, packet, MrcMessageRelayStore::PKSRC_DATABASE);

	MrcRecvContext ctx(hash, source, _pSwarmAddress);
	_OnMessageCallback((MrcMessage*)&packet, ctx);
}


void MrcMessageRelaySwarm::_ReponseStatus(const MrcDagStatus& remote_status, const NetworkAddress& peer_addr)
{
	// find which MrcMsgHash is not exist in local
	_Store.SearchMissing(remote_status,
		[this, peer_addr](MrcMsgHash hash)
		{
			_Request(hash, &peer_addr);
		}
	);
	
	rt::BufferEx<BYTE> buf;
	auto* local_status = _Store.BuildStatus(buf);
	if(local_status)
		_SendStatus(false, *local_status, &peer_addr);
}


void MrcMessageRelaySwarm::_AppenLayeredHeader(const Packet& src, Packet& dst)
{
	UINT all_size = sizeof(_details::MrcFragmentedHeader) + src.GetLength();
	LPSTR pdata = dst.Claim(all_size);
	dst.Commit(all_size);
	auto& layered_header = *(_details::MrcFragmentedHeader*)pdata;
	layered_header.Magic = MRC_PROTOCOL_CHAR_EXT_SWARM;
	layered_header.CP_ID = CP_ID_Array[CP_ID_COUNT/2];
	memcpy(pdata + sizeof(_details::MrcFragmentedHeader), src.GetData(), src.GetLength());
}


bool MrcMessageRelaySwarm::_NetCore_Send(Packet& packet, const NetworkAddress& to, PACKET_SENDING_FLAG flag)
{
	if(_bExtended)
	{
		PacketBuf<MRC_PACKET_BUFSIZE> new_packet;
		_AppenLayeredHeader(packet, new_packet);

		return _pNetCore->Send(new_packet, to, flag);
	}
	else
		return _pNetCore->Send(packet, to, flag);
}

int	MrcMessageRelaySwarm::_NetCore_Broadcast(Packet& packet, const NetworkAddress* skip, PACKET_SENDING_FLAG flag)
{
	if(_bExtended)
	{
		PacketBuf<MRC_PACKET_BUFSIZE> new_packet;
		_AppenLayeredHeader(packet, new_packet);

		return _pNetCore->SMB().Broadcast(new_packet, _SwarmId, skip, flag);
	}
	else
		return _pNetCore->SMB().Broadcast(packet, _SwarmId, skip, flag);
}


bool MrcMessageRelaySwarm::_Send(Packet& packet, const NetworkAddress& to, PACKET_SENDING_FLAG flag)
{
	const uint8_t* packet_data = (uint8_t*)packet.GetData();
	const int   packet_length = packet.GetLength();

	/*
	if(packet_length < MRC_SIZE_EDGE)
		return _NetCore_Send(packet, to, flag);
	*/
	{
		auto  r = _NetCore_Send(packet, to, flag);
		if(packet_length < _details::MrcFragmentAssembler::SIZE_EDGE) return r;
	}


	// Fragement ONLY for MrcHeader::OP_MESSAGE_CONTENT
	if(MrcHeader::CheckOpCode(packet_data) != MrcHeader::OP_MESSAGE_CONTENT)
		return false;

	const auto* dag_packet = (MrcMessage*)(packet_data + sizeof(MrcHeader));
	_details::MrcFragmentAssembler::FRAGMENT_ID id = dag_packet->GetMessageCrc();

	PacketBuf<> buf;
	int r;

	for(auto i=0; /* */; i++)
	{
		r = _details::BuildMrcFragmentPacket(packet, id, i, buf);
		if(r >= 0)
		{
			if(!_NetCore_Send(buf, to, flag))
				return false;
		}
		if(r <= 0) break;
	}

	return true;
}

int MrcMessageRelaySwarm::_Broadcast(Packet& packet, const NetworkAddress* skip, PACKET_SENDING_FLAG flag)
{
	const uint8_t* packet_data = (uint8_t*)packet.GetData();
	const int   packet_length = packet.GetLength();

	/*
	if(packet_length < MRC_SIZE_EDGE)
		return _NetCore_Broadcast(packet, skip, flag);
	*/
	{
		auto  r = _NetCore_Broadcast(packet, skip, flag);
		if(packet_length < _details::MrcFragmentAssembler::SIZE_EDGE) return r;
	}

	// Fragement ONLY for MrcHeader::OP_MESSAGE_CONTENT
	if(MrcHeader::CheckOpCode(packet_data) != MrcHeader::OP_MESSAGE_CONTENT)
		return false;

	const auto* dag_packet = (MrcMessage*)(packet_data + sizeof(MrcHeader));
	_details::MrcFragmentAssembler::FRAGMENT_ID id = dag_packet->GetMessageCrc();

	PacketBuf<> buf;
	int r;

	for(auto i = 0; /* */; i++)
	{
		r = _details::BuildMrcFragmentPacket(packet, id, i, buf);
		if(r >= 0)
		{
			if(!_NetCore_Broadcast(buf, skip, flag))
				return false;
		}
		if(r <= 0) break;
	}

	return true;
}


void MrcMessageRelaySwarm::OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx, bool pure)
{
	if(ctx.pRelayPeer)return; // relay not allowed

#ifndef	NDEBUG
	// random drop packets to simulate network
	if(_details::_MRC_LOSS_RATE_)
	{
		static rt::Randomizer rng(os::TickCount::Get());
		if(rng.GetNext() % 1000 < _details::_MRC_LOSS_RATE_)
		{
			MRC_TRACE("Drop Packet!");
			return;
		}
	}
#endif

	if(_bExtended && !pure)
	{
		if(len < sizeof(_details::MrcFragmentedHeader)) return;
		pData = (LPBYTE)pData + sizeof(_details::MrcFragmentedHeader);
		len -= sizeof(_details::MrcFragmentedHeader);
	}
	
	MrcHeader* lpHeader = (MrcHeader*)pData;

	switch (lpHeader->OpCode)
	{
		case MrcHeader::OP_MESSAGE_CONTENT:
		{
			MrcMessage& packet = *((MrcMessage*)((LPBYTE)pData + sizeof(MrcHeader)));

			if(!packet.IsValidSize((int)len - sizeof(MrcHeader)))
			{
				MRC_TRACE("[MrcMessageRelaySwarm::_OnRecv::MrcHeader::OP_MESSAGE_CONTENT] Recv Error Fromat Data, Drop it !");
				return;
			}

			if(!packet.IsValidPow())return;

			_UpdateRecvLocalTime();
			_UpdateRecvMsgLocalTime();

			if(packet.GetExpirationTime() < _Store._Status.NOW || packet.GetTime() > _Store._Status.TIME_Acceptable)
				return;

			MRC_TRACE("packet from:" << tos(ctx.RecvFrom)<<", size:"<<len << ", hash:" << packet.GetHashValue());

			auto hash = packet.GetHashValue();
			MrcMessage* pDPK = _Store.Put(
				hash,
				packet, 
				ctx.RecvFrom.IsEmpty() ? MrcMessageRelayStore::PKSRC_LOCALHOST: MrcMessageRelayStore::PKSRC_NETWORK
			);

			// recv new one, callback & broadcast
			if(pDPK)
			{
				MrcRecvContext msg_ctx(MrcMsgHashToMsgCrc(hash), ctx.RecvFrom.IsEmpty() ? MrcRecvContext::SourceLoopback : MrcRecvContext::SourceNetwork, _pSwarmAddress);
				_OnMessageCallback(&packet, msg_ctx);

#if defined(OSN_GHOST_NODE)
				return;
#else
				if(!ctx.RecvFrom.IsEmpty())
				{
					PacketBuf<MRC_PACKET_BUFSIZE> buf;
					buf.Append(pData, len);
					_Broadcast(buf, &ctx.RecvFrom, PSF_FORWARD_ONLY);
				}
#endif
			}
		}
		break;

		case MrcHeader::OP_MESSAGE_PULL:
		{
#if defined(OSN_GHOST_NODE)
			return;
#else
			if(len != sizeof(MrcHeader) + sizeof(MrcMsgHash))
				return;

			MrcMsgHash& hash = *((MrcMsgHash*)((LPBYTE)pData + sizeof(MrcHeader)));
			const MrcMessage* msg = _Store.Get(hash, false);
			if(msg)
			{
				_SendPacket(*msg, &ctx.RecvFrom);
			}
#endif
		}
		break;

		case MrcHeader::OP_STATUS_PING:
		{
			MrcDagStatus& status= *((MrcDagStatus*)((LPBYTE)pData + sizeof(MrcHeader)));

			if(!status.IsValid(len - sizeof(MrcHeader)))
			{
				MRC_TRACE("[MrcMessageRelaySwarm::_OnRecv::MrcHeader::OP_STATUS_PING] Recv Error Fromat Data, Drop it !");
				return;
			}

			_status_g = 0;
			_UpdateRecvLocalTime();

			MRC_TRACE("status ping from:" << tos(ctx.RecvFrom) << ", size:" << len <<", count:"<< (int)status.Count);
			_ReponseStatus(status, ctx.RecvFrom);
		}
		break;

		case MrcHeader::OP_STATUS_PONG:
		{
			MrcDagStatus& status = *((MrcDagStatus*)((LPBYTE)pData + sizeof(MrcHeader)));

			if(!status.IsValid(len - sizeof(MrcHeader)))
			{
				MRC_TRACE("[MrcMessageRelaySwarm::_OnRecv::MrcHeader::OP_STATUS_PONG] Recv Error Fromat Data, Drop it !");
				return;
			}

			_UpdateRecvLocalTime();

			MRC_TRACE("status pong from:" << tos(ctx.RecvFrom) << ", size:" << len << ", count:" << (int)status.Count);
			_Store.SearchMissing(status,
				[this, ctx](MrcMsgHash hash)
				{
					_Request(hash, &ctx.RecvFrom);
				}
			);
		}
		break;

		case MrcHeader::OP_FRAGMENT_DATA:
		{
			auto packet = _Fragments->Recv((BYTE*)pData + sizeof(MrcHeader), len - sizeof(MrcHeader));
			if(packet)
			{
				// fragment above layered, so must be pure
				OnRecv(packet->Data, packet->GetDataSize(), ctx, true);
			}
		}
		break;

		default:
		{
			// todo: record unknown packets
		}
	}
	
}

void MrcMessageRelaySwarm::OnTick(UINT tick)
{
	_UpdateStoreTime();
	_tick_count++;

	if(_tick_count % 10 == 0)
	{
		_Store.SearchMissing(
			[this](MrcMsgHash hash)
			{
				_Request(hash);
			}
		);
	}

	if(_tick_count % (500/100) ==0)
	{
		if(_status_i == 0)
			_status_v = _status_r.GetNext();

		if( _status_v & _uint_mask[_status_i] )
		{
			_status_g++;

			if(_status_g > (1 + _NetGetActiveDegree()) * (MRC_STATUS_PING_INTERVAL) / 500 / 2)
			{
				_status_g = 0;
				MRC_TRACE("broadcast status ping");
				Sync();
			}
		}

		_status_i = (_status_i + 1) % 32;
		
	}

	if(_tick_count % 600 == 0)
	{
		_Store.Thrink();
	}

	if(_tick_count % 100 == 0)
	{
		_Fragments->Recycle();
	}

}

bool MrcMessageRelaySwarm::OnCommand(const os::CommandLine& cmd, rt::String& out)
{
	rt::String_Ref cc = cmd.GetText(1);

	if(cc == "list")
	{
		rt::String s;
		_Store.Dump(s, true);
		return true;
	}

	if(cc == "show")
	{
		rt::String s;
		_Store.Dump(s);
		return true;
	}

	if(cc == "workload")
	{
		GetWorkload(out);
		return true;
	}

	return false;
}

int	MrcMessageRelaySwarm::Broadcast(const MrcMessage& packet, const NetworkAddress* skip)
{
#if defined(OSN_GHOST_NODE)
	return 0;
#else

	PacketBuf<MRC_PACKET_BUFSIZE> buf;
	MrcHeader header;
	header.Magic = MRC_PROTOCOL_CHAR_MAIN_SWARM;
	header.OpCode = MrcHeader::OP_MESSAGE_CONTENT;
	buf.Append(&header, 2);
	buf.Append(&packet, packet.GetSize());

	OnRecv(buf.GetData(), buf.GetLength(), PacketRecvContext(_details::EMPTY_ADDR, PSF_NORMAL), true);
	return _Broadcast(buf, skip, PSF_FORWARD_ONLY);
#endif
}

MrcMsgHash MrcMessageRelaySwarm::BroadcastEnvelope(const MrcEnvelope& envelope, int64_t ttl_sec, bool directly_recv_by_self)
{
#if defined(OSN_GHOST_NODE)
	return 0;
#else

	MrcMsgHash parents[MRC_PACKETS_PARENT_COUNT];
	int parent_count = _Store.PickParents(parents);
	if(parent_count == 0)
		return 0;

	PacketBuf<MRC_PACKET_BUFSIZE> buf;
	int allsz = sizeof(MrcHeader) + offsetof(MrcMessage, Parents) + parent_count * sizeof(MrcMsgHash) + envelope.GetSize();
	LPSTR pdata= buf.Claim(allsz);
	buf.Commit(allsz);

	MrcHeader& header = *(MrcHeader*)pdata;
	header.Magic = MRC_PROTOCOL_CHAR_MAIN_SWARM;
	header.OpCode = MrcHeader::OP_MESSAGE_CONTENT;

	MrcMessage& packet = *(MrcMessage*)&pdata[sizeof(MrcHeader)];
	packet.Ver = MRC_PACKETS_VERSION;
	packet.Flag = parent_count;
	packet.TTL = rt::max((ttl_sec + (3600LL * 24 - 1)) / (3600LL * 24), 2LL);
	// packet.PowNonce auto filled by CalcPow()
	for(int i = 0; i < parent_count; i++)
		packet.Parents[i] = parents[i];
	memcpy(&packet.GetEnvelope(), &envelope, envelope.GetSize());

	packet.CalcPow(); // packet finished
	ASSERT(packet.IsValidPow());

	if(directly_recv_by_self)
		OnRecv(buf.GetData(), buf.GetLength(), PacketRecvContext(_details::EMPTY_ADDR, PSF_NORMAL), true);

	_Broadcast(buf);
	return packet.GetHashValue();
#endif
}

int	MrcMessageRelaySwarm::_SendPacket(const MrcMessage& packet, const NetworkAddress* dest)
{
	PacketBuf<MRC_PACKET_BUFSIZE> buf;
	MrcHeader header;
	header.Magic = MRC_PROTOCOL_CHAR_MAIN_SWARM;
	header.OpCode = MrcHeader::OP_MESSAGE_CONTENT;
	buf.Append(&header, 2);

	int size = packet.GetSize();
	
	buf.Append(&packet, size);
	
	return _Send(buf, *dest);
}

void MrcMessageRelaySwarm::_Request(MrcMsgHash hash, const NetworkAddress* dest)
{
	MRC_TRACE("Request: "<<hash);

	PacketBuf<MRC_PACKET_BUFSIZE> buf;
	MrcHeader header;
	header.Magic = MRC_PROTOCOL_CHAR_MAIN_SWARM;
	header.OpCode = MrcHeader::OP_MESSAGE_PULL;
	buf.Append(&header, 2);
	buf.Append(&hash, sizeof(hash));

	if(dest)
	{
		_Send(buf, *dest);
	}
	else
	{
		_Broadcast(buf);
	}
}

void MrcMessageRelaySwarm::_SendStatus(bool initiative, const MrcDagStatus& status, const NetworkAddress* dest)
{
	PacketBuf<MRC_PACKET_BUFSIZE> buf;
	MrcHeader header;
	header.Magic = MRC_PROTOCOL_CHAR_MAIN_SWARM;
	header.OpCode = initiative ? MrcHeader::OP_STATUS_PING: MrcHeader::OP_STATUS_PONG;
	buf.Append(&header, 2);
	buf.Append(&status, offsetof(MrcDagStatus, Heads) + status.Count*sizeof(MrcMsgHash));

	if(dest)
	{
		_Send(buf, *dest);
	}
	else
	{
		_Broadcast(buf);
	}
}

MrcWorkload MrcMessageRelaySwarm::GetWorkload()
{
	return _Store.GetWorkload();
}

void MrcMessageRelaySwarm::GetWorkload(rt::String& out)
{
	auto ret = _Store.GetWorkload();
	out += (
		J(MRC_TotalCount) = ret.TotalCount,
		J(MRC_UnReferredCount) = ret.UnreferredCount,
		J(MRC_MissingCount) = ret.MissingCount
	);
}

void MrcMessageRelaySwarm::GetPooled(Void_Func_With_MrcMessage cb, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit)
{
	return _Store.GetPooled(cb, from, to, app, action, limit);
}


int64_t MrcMessageRelaySwarm::GetMissingTime(int64_t from)
{
	return _Store.GetMissingTime(from);
}


} // namespace upw