#include "../netsvc_core.h"
#include "../stg/storage_rocksdb.h"
#include "../gossip_nettime.h"
#include "../local_swarm.h"
#include "../swarm_broadcast.h"
#include "../dht/dht.h"
#include "../gdp/gdp.h"
#include "../mrc/mrc.h"
#include "../mlt/mlt.h"
#include "local_api.h"


namespace upw
{


bool NetworkServiceCore::OnApiInvoke(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp)
{
	if(resp->GetRequest().StartsWith("swarm."))
	{
		return OnApiInvokeSwarm(action, arguments, resp);
	}

	if(action == rt::SS("status"))
	{
		OnApiInvokeStatus(arguments, resp);
		return true;
	}
	else if(action == rt::SS("ver"))
	{
		rt::String s = NET_BUILD_INFO();
		s.Replace("  ", " ");

		resp->SendJsonReturnBegin().String(s);
		resp->SendJsonReturnEnd();
		return true;
	}
	else if(action == rt::SS("init"))
	{
		if(!_TickingThread.IsRunning())
		{
			resp->SendError(101);
			return true;
		}

		if(bInitializationFinalized)
		{
			resp->SendError(102);
			return true;
		}

		DhtAddress mrc_default_swarm;
		UINT default_swarm_id = 0;
		rt::String_Ref msgs, media, kvs, app_name;
		bool msgs_delay = false;
		bool kvs_delay = false;
		RocksMergeMode msgs_dbmode = RocksMergeMode::__Undefined;
		RocksMergeMode kvs_dbmode = RocksMergeMode::__Undefined;

		bool hob = false, mlt = false, gdp = false, pbc = false, lsm = false;

		{	// parsing arguments
			auto lookup_dbmode = [](const rt::String_Ref& flags){
				if(flags.FindString("\"db_dedicate\"") > 0)return RocksMergeMode::Dedicated;
				if(flags.FindString("\"db_separate\"") > 0)return RocksMergeMode::Separated;
				if(flags.FindString("\"db_single\"") > 0)return RocksMergeMode::All;
				return RocksMergeMode::Separated;
			};

			rt::JsonObject json(arguments);
			rt::JsonKeyValuePair kv;
			while(json.GetNextKeyValuePair(kv))
			{
				static const char* sz_delay_load = "\"delay_load\"";
				static const char* sz_flag = "flags";

				if(kv.GetKey() == rt::SS("mrc"))
				{
					ASSERT(_pSMB);
					if(msgs_dbmode != RocksMergeMode::__Undefined)continue;

					rt::JsonObject arg(kv.GetValue());
					msgs = arg.GetValue("msgs_dir");

					if(msgs.IsEmpty())
					{
						resp->SendError(103, "mrc.msgs_dir");
						return true;
					}

					media = arg.GetValue("media_dir");
					if(!media.IsEmpty())gdp = true;

					rt::String_Ref str = arg.GetValue(sz_flag);
					msgs_delay = str.FindString(sz_delay_load) > 0;
					msgs_dbmode = lookup_dbmode(str);

					rt::Zero(mrc_default_swarm);
					str = arg.GetValue("default_swarm");
					if(str.IsEmpty())
					{
						default_swarm_id = _pSMB->GetDefaultSwarmId();
						if(default_swarm_id == SWARM_ID_INVALID)
						{
							resp->SendError(106);
							return true;
						}
					}
					else
					{
						if(!mrc_default_swarm.FromString(str))
						{
							resp->SendError(107, str);
							return true;
						}
					}
				}
				else if(kv.GetKey() == rt::SS("kvs"))
				{
					ASSERT(_pSMB);
					if(kvs_dbmode != RocksMergeMode::__Undefined)continue;

					rt::JsonObject arg(kv.GetValue());
					kvs = arg.GetValue("kv_dir");

					if(kvs.IsEmpty())
					{
						resp->SendError(103, "kvs.kv_dir");
						return true;
					}
					rt::String_Ref flag = arg.GetValue(sz_flag);
					kvs_delay = flag.FindString(sz_delay_load) > 0;
					kvs_dbmode = lookup_dbmode(flag);
					gdp = true;
				}
				else if(kv.GetKey() == "hob")hob = true;
				else if(kv.GetKey() == "mlt")mlt = true;
				else if(kv.GetKey() == "gdp")gdp = true;
				else if(kv.GetKey() == "pbc")pbc = true;
				else if(kv.GetKey() == "lsm")lsm = true;
				else if(kv.GetKey() == "app_name")app_name = kv.GetValue();
				else
				{
					resp->SendError(105, kv.GetKey());
					return true;
				}
			}

			if(app_name.IsEmpty())
			{
				resp->SendError(109, "app_name");
				return true;
			}
		}

		auto set_netsvc = [this](NETWORK_SERVICE_TAG svc){
			_NodeServiceActivated |= svc;
			if(svc < NETSVC_MASK_REPORTING)
				_NodeDesc.ServicesActivated |= svc;
		};

		SetAppNames(app_name);

		auto& ret = resp->SendJsonReturnBegin().Object();
		if(hob)
		{
			set_netsvc(NETSVC_HOB);
			ret.AppendKey("hob", true);
		}

		if(mlt)
		{
			if(!_pMLT){ VERIFY(_pMLT = _New(MultiLinkTunnels(this))); }
			set_netsvc(NETSVC_MLT);
			ret.AppendKey("mlt", true);
		}

		if(gdp)
		{
			if(!_pGDP)VERIFY(_pGDP = _New(GossipDataPropagation(this)));
			set_netsvc(NETSVC_GDP);
			ret.AppendKey("gdp", true);
		}

		if(lsm)
		{
			if(!_pLSM)
			{
				VERIFY(_pLSM = _New(LocalSwarm(this, _NodeDesc, NET_LOCALSWRAM_EXPECTED_PEER_COUNT)));
				_UpdateLocalSwarmBroadcastAddresses();
			}
			set_netsvc(NETSVC_LSM);
			ret.AppendKey("lsm", true);
		}

		if(pbc)
		{
			set_netsvc(NETSVC_PBC);
			ret.AppendKey("pbc", true);
		}

		if(	msgs_dbmode != RocksMergeMode::__Undefined || 
			kvs_dbmode != RocksMergeMode::__Undefined
		)
		{
			bool mrc_init = false, mds_init = false, kvs_init = false;

			_pStorageFactoryByApi = AllocateUnifiedStorageFactory(msgs, msgs_dbmode, media, kvs, kvs_dbmode);
			ASSERT(_pStorageFactoryByApi);

			if(msgs_dbmode != RocksMergeMode::__Undefined)
			{
				UINT swarm_id;
				if(	(mrc_default_swarm.IsZero() && (swarm_id = _pSMB->GetDefaultSwarmId()) != SWARM_ID_INVALID) ||
					(!mrc_default_swarm.IsZero() && (swarm_id = _pSMB->Join(mrc_default_swarm, 8)))
				)
				{
					ASSERT(!_pMRC);
					VERIFY(_pMRC = _New(MessageRelayCore(this)));
					mrc_init = _pMRC->Init(swarm_id, _pStorageFactoryByApi, msgs_delay);
					ret.AppendKey("mrc", mrc_init);
					if(mrc_init && !media.IsEmpty())
						ret.AppendKey("mds", _pMRC->HasMediaCore());
				}
			}

			if(kvs_dbmode != RocksMergeMode::__Undefined)
			{
				// TBD

				ret.AppendKey("kvs", kvs_init);
			}

			if(!mrc_init && !kvs_init)
				_SafeRelease(_pStorageFactoryByApi);
		}

		resp->SendJsonReturnEnd();
		bInitializationFinalized = true;
		return true;
	}
	else if(action == rt::SS("load_delayed"))
	{
		if(!bInitializationFinalized)
		{
			resp->SendError(108);
			return true;
		}

		if(_DataServiceSuspended)
			ResumeDataService();

		auto& ret = resp->SendJsonReturnBegin().Object();

		if(_pMRC && _pMRC->IsMediaCoreDelayed())
		{
			_pMRC->ResumeMediaCore();
			ret.AppendKey("mds", true);
		}

		// TBD, loading KVS ...

		resp->SendJsonReturnEnd();
		return true;
	}
	else if(action == rt::SS("shutdown"))
	{
		_LOG("[API]: core shutdown ...");
		bWantStop = true;
		CoreEvent(MODULE_CORE, CORE_EXIT);

		resp->SendJsonReturnBegin().Boolean(true);
		resp->SendJsonReturnEnd();
		return true;
	}
	else if(action == rt::SS("time"))
	{
		resp->YieldPolling([this](LocalApiResponder* resp){
			resp->SendJsonReturnBegin().Object((
				J(time) = GetNetworkTime(),
				J(deviation) = GNT().GetTimeDrift(),
				J(stablity) = GNT().GetStablizationDegree()
			));
			resp->SendJsonReturnEnd();
			return true;
		});

		return true;
	}

	return false;
}

bool NetworkServiceCore::OnApiInvokeSwarm(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp)
{
	if(action == rt::SS("join"))
	{
		
	}

	return false;
}

void NetworkServiceCore::OnApiInvokeStatus(const rt::String_Ref& arguments, LocalApiResponder* resp)
{
	static const rt::SS net_states[] = {
		"disconnected", "private", "intranet", "public", "private+upnp", "intranet+upnp"
	};

	int conn = _ConnectionState;
	if((conn == 1 || conn == 2) && _NatMappingState == LNS_MAPPED)
		conn += 3;

	auto& ret = resp->SendJsonReturnBegin();
	ret.Object((
		J(initialized) = bInitializationFinalized,
		J(internet) = net_states[conn],
		J_IF(_pGNT, J(net_time) = JA(GetNetworkTime(), _pGNT->GetTimeDrift(), _pGNT->IsStablized(), _pGNT->IsCasting())),
		J_IF(_pDHT, J(dht_nodes) = JA(_pDHT->GetRoutingTableSize(), _pDHT->GetRoutingTableSizeIPv6())),
		J_IF(_pLSM, J(nearby) = _pLSM->GetPeerCount())
	));

	{	
		auto m = ret.ScopeAppendingKey("modules");
		{	
			ret.Array();
			if(NETSVC_PBC&_NodeServiceActivated)ret.AppendElement("pbc");
			if(NETSVC_CONSOLE&_NodeServiceActivated)ret.AppendElement("con");
			if(NETSVC_NAT&_NodeServiceActivated)ret.AppendElement("nat");
			if(NETSVC_HOB&_NodeServiceActivated)ret.AppendElement("hob");
			if(_pGNT)ret.AppendElement("gnt");
			if(_pDHT)ret.AppendElement("dht");
			if(_pLSM)ret.AppendElement("lsm");
			if(_pGDP)ret.AppendElement("gdp");
			if(_pMLT)ret.AppendElement("mlt");
			if(_pMRC)
			{	ret.AppendElement("mrc");
				if(_pMRC->HasMediaCore())
					ret.AppendElement("dms"); // offload media
			}
		}
	}

	if(_pMRC)
	{
		auto m = ret.ScopeAppendingKey("mrc");
		ret.Object();

		auto& cc = _pMRC->GetContactsControl();
		if(cc.HasContracts())
		{
			auto* c = cc.GetContacts();
			auto mc = c->GetMyself();
			MrcContactProfile profile;
			if(mc && c->GetProfile(mc, &profile))
			{
				ret.ScopeAppendingKey("user")->Object((
					J(pk) = tos_base32(*c->GetPublicKey(mc)),
					J(name) = profile.Name
				));
			}
		}

		if(_pMRC->HasMediaCore())
		{
			MrcMediaWorkload load = _pMRC->GetMediaWorkload();
			ret.ScopeAppendingKey("media")->Object((
				J(total) = JA(load.TotalBytes, load.TotalCount),
				J(avail) = JA(load.AvailableBytes, load.AvailableCount),
				J(miss) = JA(load.MissingBytes, load.MissingCount)
			));
		}
	}
		
	if(_pSMB)
	{
		rt::BufferEx<DhtAddress> list;
		_pSMB->GetSwarmAddresses(list);

		auto s = ret.ScopeAppendingKey("swarms");
		ret.Object();

		UINT default_swarm = _pSMB->GetDefaultSwarmId();
		for(auto& d : list)
		{
			UINT sid = _pSMB->GetSwarmIdFromAddress(d);

			auto w = ret.ScopeAppendingKey(tos(d));
			ret.Object();
			if(sid == default_swarm)
				ret.AppendKey("default", true);

			if(_pDHT)
			{
				auto* sw = _pDHT->GetSwarm(sid);
				if(sw)
				{
					auto& l = sw->GetPeers();
					ret.MergeObject((
						J(forward_peers) = l.ForwardCount,
						J(backward_peers) = l.BackwardCount
					));
				}
			}

			MrcWorkload load;
			if(_pMRC && _pMRC->GetWorkload(load, &d))
			{
				ret.ScopeAppendingKey("msgs")->Object((
					J(total) = load.TotalCount,
					J(unref) = load.UnreferredCount,
					J(miss) = load.UnreferredCount
				));
			}

			// TBD: KVS
		}
	}

	if(_pGDP)
	{
		auto load = _pGDP->GetWorkload();
		ret.ScopeAppendingKey("transfer")->Object((
			J(request) = JA(load.TotalBytes, load.TotalCount),
			J(finish) = JA(load.FinishedBytes, load.FinishedCount),
			J(syncing) = JA(load.WorkingBytes, load.WorkingCount),
			J(discard) = JA(load.DropedBytes, load.DropedCount)
		));
	}

	resp->SendJsonReturnEnd();
}


} // namespace upw