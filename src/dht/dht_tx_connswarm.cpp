#include "../netsvc_core.h"
#include "dht.h"
#include "dht_tx_connswarm.h"

namespace upw
{

DhtTxConnSwarm::DhtTxConnSwarm(const DhtAddress& target, 
                                   MainlineDHT& dht, 
								   UINT expected_num, 
								   const DhtAddress* nodeid, 
								   DWORD app, 
                                   const DhtAddress* private_secret,
								   const rt::String_Ref& boot_file)
	:DhtTxSwarm(target,dht,expected_num,nodeid,app,private_secret,boot_file)
{
	_TX_TYPE = TX_TYPE;
}

void DhtTxConnSwarm::OnReply(const DhtTxReplyContext& rc)
{
	ASSERT(IsLockedByCurrentThread());
	NET_DEBUG_LOG("reply: "<<tos(rc.recvctx->RecvFrom));

	auto& msg = rc.msg;
	ASSERT(msg.fields_parsed&MSGFIELD_R_ID);

	if(!msg.swarm_member)
		NET_DEBUG_LOG("non-member peers: "<<tos(rc.recvctx->RecvFrom)<<" Host="<<_RecentQueriedHosts.size());

	float latency = rc.GetLatency();
	auto contact_stat = _OnSwarmPeerContacted(msg, *rc.recvctx, rc.tick, latency, msg.swarm_member, false);
	bool in_peerlist = msg.swarm_member && (contact_stat != SPC_REJECT);

	// collect network time sample
	bool time_sampled = false;
	if(in_peerlist && rc.msg.node_desc.LocalTime32)
		time_sampled = _DHT.GetCore()->SampleNetworkTime(rc.msg.node_desc.LocalTime32, (UINT)((latency + 1.25f)*NET_TICK_UNIT_FLOAT + 0.5f), *rc.recvctx);
	
	if(	contact_stat == SPC_ADDED && 
			(	(time_sampled && !_DHT.GetCore()->IsNetworkTimeStablized()) ||
				(rc.recvctx->SendingFlag & PSF_IP_RESTRICTED_VERIFIED) == 0
			)
	)
	{	// ping with sec packet, again
		_SendContactMessage(rc.recvctx->RecvFrom, true, false, PSF_OBFUSCATION);
	}

	if(!IsMature() || !_DHT.GetCore()->IsNetworkTimeStablized())
	{
		if((msg.fields_parsed&MSGFIELD_PEERS) && msg.peers_count)
		{
			NET_DEBUG_LOG("msg.peers_count = "<<msg.peers_count);
			_SendContactMessageToPeers(msg.peers, msg.peers_count);
		}

		if((msg.fields_parsed&MSGFIELD_ALTVALS) && msg.alt_peers_count)
		{
			NET_DEBUG_LOG("msg.alt_peers_count = "<<msg.alt_peers_count);
			_SendContactMessageToPeers(msg.alt_peers, msg.alt_peers_count);
		}
	}

	if(_IsActiveDiscovering())
	{
		if((msg.fields_parsed&MSGFIELD_NODES) && msg.nodes_size)
		{
			NET_DEBUG_LOG("msg.nodes_size = "<<msg.nodes_size);
			for(UINT i=0;i<msg.nodes_size;i++)
			{
				const DhtMessageParse::dht_compact_node& n = msg.nodes[i];
				if(!_IsNodesFull() && IsQueryAllowed(n.NetAddress))
				{
					_SendContactMessage(NetworkAddress(n.NetAddress), false, false, PSF_DROPABLE);
				}
				else
				{	//NET_DEBUG_LOG("skip: "<<tos(msg.peers[i]));
				}
			}
		}

		if((msg.fields_parsed&MSGFIELD_NODES6) && msg.nodes6_size)
		{
			NET_DEBUG_LOG("msg.nodes6_size = "<<msg.nodes6_size);
			for(UINT i=0;i<msg.nodes6_size;i++)
			{
				const DhtMessageParse::dht_compact_node_v6& n = msg.nodes6[i];
				if(!_IsNodesFull() && IsQueryAllowed(n.NetAddress))
				{
					_SendContactMessage(NetworkAddress(n.NetAddress), false, false, PSF_DROPABLE);
				}
				else
				{	//NET_DEBUG_LOG("skip: "<<tos(n.NetAddress));
				}
			}
		}

		if(_RecentQueriedHosts.size() + _RecentQueriedHostsV6.size() > _RecentQueriedHostsLimit)
			_StopAllActiveWorks();
	}
}

namespace _details
{



} // namespace _details

DhtTxConnSwarm::SwarmPeerContact DhtTxConnSwarm::_OnSwarmPeerContacted(const DhtMessageParse& msg, const PacketRecvContext& ctx, UINT tick, float latency, bool auto_add, bool query)
{
	if(msg.r_id == _NodeId)return SPC_REJECT;

	bool is_sec = ctx.SendingFlag&PSF_IP_RESTRICTED_VERIFIED;

	auto& swarm_peers = _SwarmPeers;
	auto& dirty = _SwarmPeersDirty;

	SwarmPeerContact ret = SPC_UPDATED;

	int s;
	for(UINT i=0; i<swarm_peers.GetSize(); i++)
	{
		if( true == swarm_peers[i].IsForward() && 
			swarm_peers[i].DhtAddress == msg.r_id)
		{
			if(swarm_peers[i].NetAddress == ctx.RecvFrom ||
			   swarm_peers[i].AlternativeIP == ctx.RecvFrom)
			{	// existing peer
				swarm_peers[i].last_recv = tick;
				if(query)swarm_peers[i].LastQueryRecv = tick;

				swarm_peers[i].UpdateLatency(latency);
			
				if(is_sec)
				{
					if(!swarm_peers[i].IpRestrictVerified())
					{
						dirty = true;
						swarm_peers[i].Flag |= NODE_IPRESTRICTVERIFIED;

						_RemoveDuplicatedInsecurePeers(swarm_peers, i+1, i+1, ctx.RecvFrom.Type(), true, msg.r_id);
					}
				}

				_UpdateNodeAuxInfo(swarm_peers[i], msg, ctx.RecvFrom);

				s = i;
				goto SORT_PEERS;
			}
			else if(!swarm_peers[i].IpRestrictVerified() && is_sec)
			{	// replace the insecure one with secure one, and remove all insecure ones with the same dht address
				auto_add = true;
				_RejectPeer(swarm_peers[i].NetAddress);

				_RemoveDuplicatedInsecurePeers(swarm_peers, i, i+1, ctx.RecvFrom.Type(), true, msg.r_id);
				break;
			}
			else if(swarm_peers[i].IpRestrictVerified() && !is_sec)
			{
				// insecure one will be discarded if the secure one exists
				_RejectPeer(ctx.RecvFrom);
				return SPC_REJECT;
			}
		}
	}

	if(auto_add)
	{
		if(swarm_peers.GetSize() >= _ExpectedNum*2)
			return SPC_REJECT;

		s = (int)swarm_peers.GetSize();
		auto& n = swarm_peers.push_back();
		n.DhtAddress       = msg.r_id;
		n.discover_time    = tick;
		n.SecureL1Distance = _SecureL1Distance(msg.r_id);
		n.last_recv        = tick;
		n.last_sent        = tick;
		n.LastQueryRecv    = query ? tick : 0;
		n.latency_average  = latency > -0.00001 ? latency : _AverageLatencyForward;
		n.NetAddress       = ctx.RecvFrom;
		n.Flag             = NODE_FLAG_ZERO;
		if(ctx.SendingFlag&PSF_IP_RESTRICTED_VERIFIED)n.Flag |= NODE_IPRESTRICTVERIFIED;
		n.Flag |= NODE_FORWARD;

		rt::Zero(n.PeerDesc);
		rt::Zero(n.AlternativeIP);
		rt::Zero(n.ExternalIP);

		_UpdateNodeAuxInfo(n, msg, ctx.RecvFrom);

#if defined(OXD_NET_DEBUG_REPORT)
		NET_DEBUG_LOG("add peers: "<<tos(ctx.RecvFrom.IPv4())<<" Host="<<_RecentQueriedHosts.size());
#endif

		dirty = true;

		_InvokePeerEvent(DHT_SWARM_DROPPING, n);
		ret = SPC_ADDED;
	}
	else
		return SPC_REJECT;

SORT_PEERS:
	if(swarm_peers.GetSize() > 2)
	{
		if(s>2)
		{
			if(swarm_peers[s] < swarm_peers[1])
			{
				rt::Swap(swarm_peers[s], swarm_peers[1]);
				if(swarm_peers[1] < swarm_peers[0])
					rt::Swap(swarm_peers[0], swarm_peers[1]);
			}
		}
	}

	return ret;
}

void DhtTxConnSwarm::Awaken()
{
    EnterCSBlock(*this);
    _PingAllPeers(true);
}

bool DhtTxConnSwarm::IsMature() const 
{
	return _DiscoveredForward > _ExpectedNum/2;
}

void DhtTxConnSwarm::Iterate()
{
	ASSERT(IsLockedByCurrentThread());

	if(!_IsActiveDiscovering())
		DhtTxRecentHosts::Iterate();

	if(_SwarmPeersDirty)
	{
		_SwarmPeersBootstrapListDirty = true;

		bool m = IsMature();
		_UpdateOutputPeers(false);
		if(m != IsMature())
		{
			if(m)_SwarmBootstrapTimer.Reset();
			CoreEventWith(MODULE_NETWORK, NETWORK_SWARM_CHANGED, tos(GetTarget()));
		}
	}
	else if(_RefreshOutputPeersTimer(_DHT.GetTick()))
	{
		_UpdateOutputPeers(true);
	}

	if(_SwarmPeersBootstrapListDirty && _UpdateBootstrapFileTimer(_DHT.GetTick()))
	{
		_SwarmPeersBootstrapListDirty = false;
		_UpdateBootstrapList();
	}

	if(_IsActiveDiscovering())
	{
		if(!_ActiveDiscoveredByStockBootstrapList && 
			_SwarmPeers.GetSize() == 0 && 
			_ActiveDiscoveringStartTime + DHT_SWARM_USE_STOCK_BOOTSTRAP_AFTER < os::Timestamp::Get()
		)
		{	_ActiveDiscoveredByStockBootstrapList = true;
			_SendContactMessageFromBootstrapFile();
		}

		if(	(_SwarmPeers.GetSize() > _ExpectedNum/2) || 
			DhtTxRecentHosts::IsFull() || // hosts exhausted
			_ActiveDiscoveringStartTime + DHT_SWARM_BOOTSTRAP_TIMEOUT < os::Timestamp::Get() // timeout
		)
		{	//_LOGC("[NET]: Connect swarm "<<tos(_Target)<<" peer discovery finished." << ", IsFull:" << DhtTxRecentHosts::IsFull());
			_StopAllActiveWorks();
		}
	}

	if(_SwarmPeers.GetSize())
	{
		if(_BootstrapBoostCountDown != 0)
			_BootstrapBoostCountDown = 0;
		// ping peers
        _PingAllPeers();
	}
	else if(!_IsActiveDiscovering())
	{
		if(_BootstrapBoostCountDown && _SwarmBootstrapBoostTimer(_DHT.GetTick()))
		{
			_StartActiveDiscovery(false);
			_BootstrapBoostCountDown--;
		}
		else if(_BootstrapBoostCountDown == 0 && _SwarmBootstrapTimer(_DHT.GetTick()))
			_StartActiveDiscovery(IsMature());
	}

	if(_HostsClearTime && _HostsClearTime < os::Timestamp::Get())
	{
		DhtTxRecentHosts::Empty();
		DhtTxRecentHosts::SetCapacityHint(_ExpectedNum*60);
		DhtTxRecentHosts::SetHardLimit(_ExpectedNum*30);
		DhtTxRecentHosts::SetRecentPeriod(30000);

		_HostsClearTime = 0;
	}
}

void DhtTxConnSwarm::_UpdateOutputPeers(bool enforce)
{
	ASSERT(IsLockedByCurrentThread());

	if(!_SwarmPeersDirty && !enforce)
		return;

	UINT tick = _DHT.GetTick();

	_OutputPeers_Back->BackwardCount = 0;
	_OutputPeers_Back->ForwardCount = 0;

	thread_local rt::BufferEx<rt::PodRef<Node>> forward_sorted;
	ASSERT(forward_sorted.GetSize() == 0);

	{
		auto* fwd = _OutputPeers_Back->ForwardPeers();
		if(_SwarmPeers.GetSize() <= 2)
		{
			for(UINT i=0; i<_SwarmPeers.GetSize(); i++)
				fwd[i] = _SwarmPeers[i].NetAddress;

			_OutputPeers_Back->ForwardCount = (UINT)_SwarmPeers.GetSize();
		}
		else
		{	// keep first 2 with best latency
			_OutputPeers_Back->ForwardCount = 2;
			fwd[0] = _SwarmPeers[0].NetAddress;
			fwd[1] = _SwarmPeers[1].NetAddress;

			ASSERT(forward_sorted.GetSize() == 0);
			struct compr_L1distance
			{	bool operator ()(const rt::PodRef<Node>& a, const rt::PodRef<Node>& b) const
				{ return a->SecureL1Distance < b->SecureL1Distance; }
			};

			compr_L1distance c;
			for(UINT i=2; i<_SwarmPeers.GetSize(); i++)
			{
				if(_SwarmPeers[i].IsAlive(tick) && _SwarmPeers[i].IpRestrictVerified())
					forward_sorted.PushSorted(_SwarmPeers[i], c);
				else
					_SwarmPeers[i].Flag |= NODE_DISCARD;
			}

			bool remove = false;
			if(forward_sorted.GetSize() > _ExpectedNum)
			{
				for(UINT i=_ExpectedNum; i<forward_sorted.GetSize(); i++)
				{
					if(forward_sorted[i]->Age(tick) > DHT_SWARM_STABLE_AGE)
					{	
						forward_sorted[i]->Flag |= NODE_DISCARD;
						_RejectPeer(forward_sorted[i]->NetAddress);
						remove = true;
					}
				}
			}

			forward_sorted.ShrinkSize(_ExpectedNum - 2);
			_OutputPeers_Back->ForwardCount += (UINT)forward_sorted.GetSize();

			for(UINT i=0; i<forward_sorted.GetSize(); i++)
				fwd[i+2] = forward_sorted[i]->NetAddress;
			forward_sorted.ShrinkSize(0);

			if(remove)
			{
				UINT i=2;
				for(; i<_SwarmPeers.GetSize(); i++)
					if(_SwarmPeers[i].Flag&NODE_DISCARD)
						break;

				ASSERT(i<_SwarmPeers.GetSize());
				UINT new_size = i;
				
				for(; i<_SwarmPeers.GetSize(); i++)
				{
					if(_SwarmPeers[i].Flag&NODE_DISCARD)
						continue;

					_SwarmPeers[new_size++] = _SwarmPeers[i];
				}

				_SwarmPeers.ShrinkSize(new_size);
			}
		}
	}

	_SwarmPeersDirty = false;

	rt::Swap(_OutputPeers_Front, _OutputPeers_Back);
	_DiscoveredForward = (UINT)_SwarmPeers.GetSize();

	_CheckHeap;
	ASSERT(_OutputPeers_Front->TotalCount() <= _ExpectedNum*2);
	ASSERT(_OutputPeers_Back->TotalCount() <= _ExpectedNum*2);
}

void DhtTxConnSwarm::_UpdateBootstrapList()
{
	ASSERT(IsLockedByCurrentThread());

	ext::fast_map<NetworkAddress, NetworkAddress> list;
	if(_SwarmPeers.GetSize() == 0)return;

	for(auto& p : _SwarmPeers)list.insert(std::make_pair(p.NetAddress, p.AlternativeIP));

    // unlock don't let file I/O block the swarm processing
	Unlock();

	auto& addr = this->GetTarget();
	rt::String fn = _DHT.GetCore()->GetCachePath() + '/' + rt::tos::Base32LowercaseOnStack<>(addr) + DHT_CONNSWARM_BOOTSTRAP_EXTNAME;

	_details::LoadSwarmNetworkAddressTable(fn, list, DHT_BOOTSTRAP_NODES_MAX);

	if(!_details::SaveSwarmNetworkAddressTable(fn, list))
		_LOG_WARNING("Failed to save swarm bootstrap list: "<<fn);

	Lock();
}

void DhtTxConnSwarm::Jsonify(rt::Json& json) const
{
	DhtTxSwarm::Jsonify(json);
	json.ScopeAppendingKey("peers")->Number(_SwarmPeers.GetSize());
}

void DhtTxConnSwarm::_StopAllActiveWorks()
{
	ASSERT(IsLockedByCurrentThread());

	_HostsClearTime = os::Timestamp::Get() + DHT_SWARM_HOSTS_FORGET_INTERVAL;
	_ActiveDiscoveringStartTime = 0;
}

void DhtTxConnSwarm::_PingAllPeers(bool force)
{
    bool no_discover = (IsMature() || _IsNodesFull()) && _DHT.GetCore()->IsNetworkTimeStablized();

    if(force || _PingPeersForwardTimer((int)_DHT.GetTick()))
        _AverageLatencyForward = _PingScan(no_discover, force, _SwarmPeers);
}

void DhtTxConnSwarm::GetStateReport(rt::String& out, UINT tick)
{
	EnterCSBlock(*this);

	out +=	rt::SS("#") + rt::tos::Number(_TX).LeftAlign(3) + "Swarm: " + tos(GetTarget()) + 
			rt::SS("\n    Node:  ") + tos(_NodeId) + 
			"\nPeers:" + _SwarmPeers.GetSize() + '/' + _ExpectedNum + 
			" LNTC:" + (int)(_AverageLatencyForward*NET_TICK_UNIT_FLOAT + 0.5f) + 
			" HOSTS:" + (int)_RecentQueriedHosts.size() + '/' + (int)_RecentQueriedHostsV6.size();

	if(!IsMature())out +=  " Immature";
	if(_IsPrivateSwarm)out +=  " Private";
	if(_IsActiveDiscovering())out += " Discovering";
	out += '\n';

	_PrintPeers(true, _SwarmPeers, out);
}

void DhtTxConnSwarm::_SendContactMessageToPeers(const NetworkAddress* peers, uint32_t count)
{
	for(uint32_t i=0; i<count; i++)
	{
		auto& p = peers[i];
		if(	(_SwarmPeers.GetSize() < _ExpectedNum || !_DHT.GetCore()->IsNetworkTimeStablized())
				&& IsQueryAllowed(p)
		)
		{	_SendContactMessage(p, _IsNodesFull(), false, PSF_DROPABLE|PSF_OBFUSCATION);
		}
		//else
		//{	NET_DEBUG_LOG("skip: "<<tos(p));
		//}
	}
}

} // namespace upw
