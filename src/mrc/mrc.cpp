//#include <functional>
#include "mrc.h"
#include "mrc_message.h"
#include "mrc_media_core.h"
#include "../netsvc_core.h"
#include "../api/local_api.h"
#include "../swarm_broadcast.h"
#include "mrc_dissemble.h"


namespace upw
{

bool MessageRelayCore::Init(UINT def_swarm_id, StorageFactory* storage_factory, bool media_core_suspended) 
{ 
	_pNetCore->SetPacketOnRecvCallBack(MRC_PROTOCOL_CHAR_MAIN_SWARM, this, &MessageRelayCore::_OnRecvInMainSwarm);
	_pNetCore->SetPacketOnRecvCallBack(MRC_PROTOCOL_CHAR_EXT_SWARM, this, &MessageRelayCore::_OnRecvInExtendedSwarm);

	_ExtendedSwarms.Init(storage_factory);

	if(_MainSwarm.Init(def_swarm_id, storage_factory, true))
	{
		auto media_store = storage_factory->CreateMediaRelayStorage();
		if(media_store.pBlobs)
		{
			ASSERT(_pMediaRelay == nullptr);
			_pMediaRelay = _New(MrcMediaRelayCore(*this));
			if(!_pMediaRelay->Init(def_swarm_id, media_store, media_core_suspended))
			{
				_SafeDel(_pMediaRelay);
				_LOG_WARNING("[MRC]: MrcMediaRelayCore failed to initialize");
			}

			_ContactsControl._pMediaRelay = _pMediaRelay;
		}

		_pStorageFactory = storage_factory;
		if(_pNetCore->HasAPI())
		{
			_pNetCore->API().SetCommandExtension("msg", this, &MessageRelayCore::_OnCommand);
			_pNetCore->API().SetApiHandler("social", this);
			_pNetCore->API().SetApiHandler("msg", this);
		}
		return true;
	}

	return false;
}

void MessageRelayCore::OnTick(UINT tick)
{
	_MainSwarm.OnTick(tick);
	_ExtendedSwarms.OnTick(tick);
	if(_pMediaRelay)_pMediaRelay->OnTick(tick);

	if(tick%100 == 30)  // 10 second interval
		_ContactsControl._10SecondTick(_pNetCore->GetNetworkTime());
}

void MessageRelayCore::DiscoverOffloadsMediaFromAnonymousMessage(const MrcEnvelope& msg, const DhtAddress* swarm_addr)
{
	if(HasMediaCore())
	{
		auto* offloads = msg.GetPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS);
		if(offloads && !offloads->IsEncrypted())
		{
			auto& list = *(MrcMediaOffloads*)offloads->Data;
			if(list.Count*sizeof(MrcMediaOffload) + offsetof(MrcMediaOffloads, Entries) == offloads->GetOriginalDataSize())
			{
				for(int i=0; i<list.Count; i++)
					_pMediaRelay->MediaOffloadDiscovered(list.Entries[i], nullptr, swarm_addr);
			}
		}
	}
}

bool MessageRelayCore::_OnMsgDefault(const MrcMessage* msg, MrcRecvContext& ctx)
{
	if(_ContactsControl.HasContracts())
	{
		// attempt decryption
		thread_local MrcMessageDisassembler parser(*this);
		parser.Clear();

		if(parser.Unseal(&msg->GetEnvelope(), ctx))
		{
			return parser.HandleControlMessage(ctx);
		}
	}
	
	DiscoverOffloadsMediaFromAnonymousMessage(msg->GetEnvelope(), ctx.SwarmAddr);
	return false;
}

void MessageRelayCore::_OnRecvInMainSwarm(LPCVOID pData, UINT len, const PacketRecvContext& ctx)
{
	_MainSwarm.OnRecv(pData, len, ctx, true);
}

void MessageRelayCore::_OnRecvInExtendedSwarm(LPCVOID pData, UINT len, const PacketRecvContext& ctx)
{
	auto* header = (_details::MrcFragmentedHeader*) pData;
	auto swarm = _ExtendedSwarms.Get(header->CP_ID);
	if(swarm)
	{
		swarm->OnRecv(pData, len, ctx, false);
	}
}

bool MessageRelayCore::Join(const DhtAddress* swarm_addr)
{
	if(_MainSwarm.SwarmAddress == *swarm_addr)
		return false;

	return _ExtendedSwarms.Get(swarm_addr, true) != nullptr;
}

bool MessageRelayCore::Leave(const DhtAddress* swarm_addr)
{
	return _ExtendedSwarms.Remove(swarm_addr);
}

bool MessageRelayCore::Active(const DhtAddress* swarm_addr)
{	
	return _ExtendedSwarms.Active(swarm_addr);
}

void MessageRelayCore::ResumeMediaCore()
{
	if(_pMediaRelay)_pMediaRelay->Resume();
}

bool MessageRelayCore::IsMediaCoreDelayed() const
{
	return _pMediaRelay && _pMediaRelay->IsSuspend();
}

void MessageRelayCore::Term()
{
	if(_pNetCore->HasAPI())
	{
		_pNetCore->API().RemoveCommandExtension("msg");
		_pNetCore->API().RemoveApiHandler("social");
		_pNetCore->API().RemoveApiHandler("msg");
	}

	_SafeDel(_pMediaRelay);

	_MainSwarm.Term();
	_ExtendedSwarms.Clear();
	_ContactsControl.Term();

	_pStorageFactory = nullptr;
}

MrcMessageRelaySwarm* MessageRelayCore::_GetMrcSwarmRelay(const DhtAddress* swarm_addr)
{
	if(!swarm_addr || _MainSwarm.SwarmAddress == *swarm_addr)
	{
		return &_MainSwarm;
	}
	else
	{
		return &(*_ExtendedSwarms.Get(swarm_addr, true));
	}
}

void MessageRelayCore::Replay(int64_t from, int64_t to, MrcRecvContext::SourceType source, const DhtAddress* swarm_addr)
{
	if(auto* dag= _GetMrcSwarmRelay(swarm_addr))
	{
		dag->Replay(from, to, source);
	}
}

void MessageRelayCore::Replay(int64_t from, int64_t to, const ext::fast_set<MrcContactPointNum>& cps, MrcRecvContext::SourceType source, const DhtAddress* swarm_addr)
{
	if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		dag->Replay(from, to, cps, source);
	}
}

void MessageRelayCore::StopReplay(const DhtAddress* swarm_addr)
{
	if (auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		dag->StopReplay();
	}
}

void MessageRelayCore::GetPooled(const DhtAddress* swarm_addr, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit, rt::String& out)
{
	MrcRecvContext context = { 0, MrcRecvContext::SourceReplayRequest,  swarm_addr, 0 };
	MrcMessageDisassembler parser(*this);
	rt::Json item;

	if (out.Last() == ']') // SendJsonReturnBegin
		out.Last() = ' ';
	else
		out = "[ ";

	auto cb = [this, &context, &parser, &item, &out](const MrcMessage& msg) -> void
	{
		item.Empty();
		parser.Clear();

		if (parser.Unseal(&msg.GetEnvelope(), context))
		{
			this->_ApiMessageJsonify(item, parser, context);
			out += item + ",";
		}
	};

	if (auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		dag->GetPooled(cb, from, to, app, action, limit);
	}

	out.Last() = ']';
}

void MessageRelayCore::GetPooled(const DhtAddress* swarm_addr, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit, LocalApiResponder* resp)
{
	MrcRecvContext context = { 0, MrcRecvContext::SourceReplayRequest,  swarm_addr, 0 };
	MrcMessageDisassembler parser(*this);
	rt::Json item;

	auto cb = [this, &context, &parser, &item, resp](const MrcMessage& msg) -> void
	{
		item.Empty();
		parser.Clear();

		if (parser.Unseal(&msg.GetEnvelope(), context))
		{
			this->_ApiMessageJsonify(item, parser, context);
			resp->SendJsonReturnBegin().Object(item);
			resp->SendJsonReturnEnd(LARE_CONTINUE);
		}
	};

	if (auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		dag->GetPooled(cb, from, to, app, action, limit);
	}

	resp->SendJsonReturnBegin().Object();
	resp->SendJsonReturnEnd(LARE_FINAL);
}

//void MessageRelayCore::Replay(osn_messages* messages, osn_recv_source source, const DhtAddress* swarm_addr)
//{
//	if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
//	{
//		dag->Replay(messages, source);
//	}
//}

int	MessageRelayCore::Broadcast(const MrcMessage& packet, const NetworkAddress* skip, const DhtAddress* swarm_addr)
{
	if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		return dag->Broadcast(packet, skip);
	}
	return 0;
}

MrcMsgHash MessageRelayCore::BroadcastEnvelope(const MrcEnvelope& envelope, int64_t ttl_sec, bool directly_recv_by_self, const DhtAddress* swarm_addr)
{
	if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		return dag->BroadcastEnvelope(envelope, ttl_sec, directly_recv_by_self);
	}
	return 0;
}

int64_t	MessageRelayCore::GetMissingTime(int64_t from, const DhtAddress* swarm_addr)
{
	if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		return dag->GetMissingTime(from);
	}
	return 0;
}

int64_t MessageRelayCore::GetLastRecvLocalTime(const DhtAddress* swarm_addr)
{
	if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		return dag->GetLastRecvLocalTime();
	}
	return 0;
}

MrcMediaWorkload MessageRelayCore::GetMediaWorkload()
{
	if(_pMediaRelay)
		return _pMediaRelay->GetWorkload();
	else
		return {0};
}

void MessageRelayCore::GetWorkload(rt::String& out, const DhtAddress* swarm_addr)
{
	if(swarm_addr&& swarm_addr->IsZero()) // output all
	{
		out += "[";

		rt::BufferEx<DhtAddress> swarms;
		_ExtendedSwarms.Dump(swarms);

		for(size_t i = 0; i <= swarms.GetSize(); i++)
		{
			bool seek_default = (i == swarms.GetSize());
			DhtAddress& swarm = seek_default ? _GetMrcSwarmRelay(nullptr)->SwarmAddress : swarms[i];

			rt::String  buf;
			GetWorkload(buf, &swarm);

			rt::Json j;
			j.Object().MergeObject(buf);
			out += (
				J(dht_address) = rt::tos::Base16(swarm),
				J(workload) = j
				);

			if(!seek_default)
				out += ",";
		}

		out += "]";

	}
	else if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		dag->GetWorkload(out);
	}
}

bool MessageRelayCore::GetWorkload(MrcWorkload& out, const DhtAddress* swarm_addr)
{
	if(auto* dag = _GetMrcSwarmRelay(swarm_addr))
	{
		out = dag->GetWorkload();
		return true;
	}

	rt::Zero(out);
	return false;
}

bool MessageRelayCore::SaveMedia(uint8_t mime, const GdpData& data, MrcMediaOffloadItem& out, const DhtAddress* swarms, uint32_t swarm_count)
{
	if(_pMediaRelay)
		return _pMediaRelay->Save(mime, data, out, swarms, swarm_count);
	else
		return false;
}

GdpData MessageRelayCore::LoadMedia(const GdpHash& hash, const GdpAsyncDataFetch* async_cb, uint8_t priority)
{
	if(_pMediaRelay)
		return _pMediaRelay->Load(hash, async_cb, priority);
	else
		return { 0, nullptr };
}

bool MessageRelayCore::LoadMedia(const GdpHash& hash, rt::BufferEx<BYTE>& out)
{
	if(_pMediaRelay)
		return _pMediaRelay->Load(hash, out);
	else
		return false;
}

int	MessageRelayCore::GetMediaAvailability(const GdpHash& hash)
{
	if(_pMediaRelay)
		return _pMediaRelay->GetAvailability(hash);
	else
		return -1;
}

void MessageRelayCore::CancelPendingLoads()
{
	if(_pMediaRelay)
		_pMediaRelay->CancelPendingLoads();
}

bool MessageRelayCore::ExportMedia(const GdpHash& hash, const char* dest, rt::String* opt_final_path)
{
	if(_pMediaRelay)
		return _pMediaRelay->Export(hash, dest, opt_final_path);
	else
		return false;
}

bool MessageRelayCore::RetainMedia(const GdpHash& hash, uint32_t ttl_days, MrcMediaOffloadItem& out)
{
	if(_pMediaRelay)
		return _pMediaRelay->RetainExistingOffload(hash, ttl_days, out);
	else
		return false;
}

LONGLONG MessageRelayCore::GetTime() const
{
	return _pNetCore->GetNetworkTime();
}

bool MessageRelayCore::GetAccessPoints(NodeAccessPoints& aps, UINT size_limit)
{
	return _pNetCore->GetNodeAccessPoints(aps, size_limit);
}

void MessageRelayCore::CleanUnusefulData(os::ProgressReport& prog)
{
	if(_pMediaRelay)
		_pMediaRelay->CleanUnusefulData(prog);
}

bool MessageRelayCore::_OnCommand(const os::CommandLine& cmd, rt::String& out)
{
	rt::String_Ref cc = rt::String_Ref(cmd.GetText(0)).TrimBefore('.');
	if(cc == "list")
	{
		rt::BufferEx<DhtAddress> swarms;
		_ExtendedSwarms.Dump(swarms);

		out += "Layered Swarms:\n";
		for(size_t i = 0; i < swarms.GetSize(); i++)
			out += "\t"+rt::tos::Base16(swarms[i]) + "\n";
		if(swarms.GetSize()==0)
			out += "\n";

		out += "Default Swarm:\n";
		out += "\t" + rt::tos::Base16(_MainSwarm.SwarmAddress) + "\n";
		
		return true;
	}
	else if(cc == "reload")
	{
		rt::String dags_txt;
		if(!os::File::LoadText("dags.txt", dags_txt)) 
			return true;
		
		rt::BufferEx<DhtAddress> targets;
		rt::BufferEx<DhtAddress> exists;
		_ExtendedSwarms.Dump(exists);

		rt::String_Ref line;
		DhtAddress dht_addr;
		while(dags_txt.GetNextLine(line))
			if(dht_addr.FromString(line))
			{
				targets.push_back(dht_addr);
				if(!_ExtendedSwarms.Get(&dht_addr, false))
					Join(&dht_addr);
			}

		for(auto i = 0; i < exists.GetSize(); i++)
		{
			bool keep_on = false;
			for(auto j = 0; j < targets.GetSize(); j++)
				if(exists[i] == targets[j])
				{
					keep_on = true;
					break;
				}
			if(!keep_on)
				Leave(&exists[i]);
		}

		return _OnCommand(os::CommandLine("dag.list"), out);
	}
	else if(cc == "workload")
	{
		DhtAddress addr = { 0 };
		GetWorkload(out, &addr);
		return true;
	}
	//else if(cc == "dht")
	//{
	//	rt::String_Ref link = rt::String_Ref(cmd.GetText(1));
	//	QRLinks::Community linkp;
	//	if(!QRLinks::ParseCommunity(link, linkp))
	//		return false;
	//	/*
	//	osn_greeting greeting;
	//	if(!osn_greeting_bylink(api_str(link), &greeting, nullptr))
	//		return false;

	//	auto& cmmt_uid = greeting.uid;
	//	api_str uid_str = osn_media_encode_base32((uint8_t*)&cmmt_uid, sizeof(cmmt_uid));

	//	auto& cmmt_addr = linkp.Address;
	//	DhtAddress dht_addr;
	//	dht_addr.FromHash(cmmt_addr, sizeof(cmmt_addr));
	//	out += (
	//			J(dht) = rt::tos::Base16(dht_addr),
	//			J(uid) = uid_str.string()
	//		);
	//	*/
	//	return true;
	//}

	return false;
}

void MessageRelayCore::UpdateContactPoints(bool contact_dirty)
{
	if(_ContactsControl._pContacts && _ContactsControl._pContacts->GetMyself())
		_ContactsControl.UpdateContactPoints(_pNetCore->GetNetworkTime(), contact_dirty);
}

void MessageRelayCore::Sync()
{
	_MainSwarm.Sync();
	_ExtendedSwarms.Sync();
}

MessageRelayCore::MessageRelayCore(NetworkServiceCore* net)
	: _pNetCore(net)
	, _MainSwarm(net, std::bind(&MessageRelayCore::_OnMsgRecv, this, std::placeholders::_1, std::placeholders::_2))
	, _ExtendedSwarms(net, std::bind(&MessageRelayCore::_OnMsgRecv, this, std::placeholders::_1, std::placeholders::_2))
{
	rt::Zero(_LocalNodeDeviceId);
	_pStorageFactory = nullptr;
}

void MrcExtMessageRelaySwarms::_Refresh_CPIDs(int64_t net_time, MrcSwarmRelayPtr& core)
{
	EnterCSBlock(_CS);

#pragma pack(push, 1)
	struct MRC_CP_Helper
	{
		int64_t					_Timestamp = 0;
		struct _Store
		{
			DhtAddress	Addr = { 0 };
			int64_t				Timestamp = 0;
		};
		union
		{
			uint8_t		_Buf[sizeof(_Store)];
			_Store		_Data;
		};

		MRC_CP_Helper(DhtAddress& addr, int64_t timestamp){ _Data.Addr = addr; _Timestamp = timestamp; }
		MrcContactPointNum CalcCPID(int slot_offset)
		{
			_Data.Timestamp = (_Timestamp / (1000 * 60 * 10)) + slot_offset;
			return (MrcContactPointNum)ipp::crc64(_Buf, sizeof(_Buf));
		}
	};
#pragma pack(pop)

	MRC_CP_Helper helper(core->SwarmAddress, net_time);

	for(auto i = 0; i < MrcMessageRelaySwarm::CP_ID_COUNT; i++)
		_CPID_Map.erase(core->CP_ID_Array[i]);

	for(auto i = 0; i < MrcMessageRelaySwarm::CP_ID_COUNT; i++)
		_CPID_Map[core->CP_ID_Array[i] = helper.CalcCPID(i - (MrcMessageRelaySwarm::CP_ID_COUNT / 2))] = core;
}

void MrcExtMessageRelaySwarms::_Refresh_All_CPIDs(int64_t net_time)
{
	EnterCSBlock(_CS);

	_CPID_Map.clear();
	ForEach([this, net_time](MrcSwarmRelayPtr& core)
	{
		_Refresh_CPIDs(net_time, core);
	});
}

MrcExtMessageRelaySwarms::MrcSwarmRelayPtr MrcExtMessageRelaySwarms::Get(MrcContactPointNum pd_id)
{
	EnterCSBlock(_CS);

	auto it = _CPID_Map.find(pd_id);

	if(it == _CPID_Map.end())
		return nullptr;
	else
		return it->second;
}

MrcExtMessageRelaySwarms::MrcSwarmRelayPtr MrcExtMessageRelaySwarms::Get(const DhtAddress* swarm_addr, bool auto_create)
{
	EnterCSBlock(_CS);

	if(_MrcSwarmRelayMap.count(*swarm_addr))
	{
		return _MrcSwarmRelayMap[*swarm_addr];
	}
	else
	{
		if(auto_create)
		{
			UINT swarm_id = _pNetCore->SMB().Join(*swarm_addr, MRC_SWARM_SIZE);

			auto swarm = std::make_shared<MrcMessageRelaySwarm>(_pNetCore, _OnMessageCallback);
			swarm->Init(swarm_id, _pStorageFactory, false);
			swarm->Replay(0, NetTimestamp::Max, MrcRecvContext::SourceReplayRequest);
			_MrcSwarmRelayMap[*swarm_addr] = swarm;
			_Refresh_CPIDs(_pNetCore->GetNetworkTime(), swarm);
			return swarm;
		}
		else
			return nullptr;
	}
}

bool MrcExtMessageRelaySwarms::Remove(const DhtAddress* swarm_addr)
{
	EnterCSBlock(_CS);

	auto swarm = Get(swarm_addr, false);
	if(!swarm) return false;

	swarm->Term();

	_MrcSwarmRelayMap.erase(*swarm_addr);

	for(auto i = 0; i < MrcMessageRelaySwarm::CP_ID_COUNT; i++)
		_CPID_Map.erase(swarm->CP_ID_Array[i]);

	return true;
}

bool MrcExtMessageRelaySwarms::Active(const DhtAddress* swarm_addr)
{
	EnterCSBlock(_CS);

	auto swarm = Get(swarm_addr, false);
	if(!swarm) return false;

	swarm->ActiveTime = os::Timestamp::Get();

	return true;
}

void MrcExtMessageRelaySwarms::DetachIdleSwarms()
{
	EnterCSBlock(_CS);
	auto all_size = _MrcSwarmRelayMap.size();
	if(all_size <= MRC_PARALLEL_SWARM_COUNT)
		return;

	std::vector<MrcSwarmRelayPtr> cores;
	cores.resize(all_size);
	int i = 0;
	for(auto& it : _MrcSwarmRelayMap)
		cores[i++] = it.second;
	std::sort(cores.begin(), cores.end(),
		[](const MrcSwarmRelayPtr& left, const MrcSwarmRelayPtr& right)
		{
			return left->GetLastRecvMsgLocalTime() > right->GetLastRecvMsgLocalTime();
		});

	for(auto i = MRC_PARALLEL_SWARM_COUNT; i < all_size; i++)
		Remove(&cores[i]->SwarmAddress);
}

bool MrcExtMessageRelaySwarms::Dump(rt::BufferEx<DhtAddress>& out)
{
	EnterCSBlock(_CS);

	size_t i = 0;
	out.SetSize(_MrcSwarmRelayMap.size());

	for(auto& it : _MrcSwarmRelayMap)
		out[i++] = it.first;

	return true;
}

void MrcExtMessageRelaySwarms::Clear()
{
	EnterCSBlock(_CS);

	for(auto& it : _MrcSwarmRelayMap)
	{
		it.second->Term();
	}

	_MrcSwarmRelayMap.clear();
}

void MrcExtMessageRelaySwarms::ForEach(std::function<void(MrcSwarmRelayPtr& core)> callback)
{
	std::vector<MrcSwarmRelayPtr> items;

	{
		EnterCSBlock(_CS);
		items.reserve(_MrcSwarmRelayMap.size());
		for(auto& it : _MrcSwarmRelayMap)
			items.push_back(it.second);
	}

	for(auto& it : items)
		callback(it);
}

void MrcExtMessageRelaySwarms::OnTick(UINT tick)
{
	static int64_t last_refresh_tm = 0;

	if(tick % 600 == 0) // 1 minite
	{
		DetachIdleSwarms();
		int64_t now = os::Timestamp::Get();
		if(now > last_refresh_tm + (int64_t)MRC_CONTACTPOINTS_DURATION)
		{
			_Refresh_All_CPIDs(_pNetCore->GetNetworkTime());
			last_refresh_tm = now;
		}
	}

	ForEach([tick](MrcSwarmRelayPtr& core)
		{
			core->OnTick(tick);
		});
}

void MrcExtMessageRelaySwarms::Sync()
{
	_Refresh_All_CPIDs(_pNetCore->GetNetworkTime());

	ForEach([](MrcSwarmRelayPtr& core)
		{
			core->Sync();
		});
}

} // namespace upw
