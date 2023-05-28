#include "dht_space.h"
#include "dht.h"


namespace upw
{

float DhtSpace::GetHighLatencyBar() const
{
	return rt::max(	DHT_SPACE_NODE_ACCEPTABLE_LATENCY/NET_TICK_UNIT_FLOAT, 
					_OverallLatency*DHT_SPACE_NODE_HIGH_LATENCY_MULTIPLIER
		   );
}

float DhtSpace::GetGoodLatencyBar() const
{
	return rt::max(	DHT_SPACE_NODE_GOOD_LATENCY/NET_TICK_UNIT_FLOAT, 
					_OverallLatency*DHT_SPACE_NODE_GOOD_LATENCY_MULTIPLIER
		   );
}

void DhtSpace::ValidateNodeIndex() const
{
#ifdef PLATFORM_DEBUG_BUILD
	for(UINT i=1;i<_TotalNodes;i++)
	{
		bool wrong = _NodeIndex[i].node->DhtAddress < _NodeIndex[i-1].node->DhtAddress;
		ASSERT(!wrong);
	}
#endif
}

bool DhtSpace::UpdateExisted(const DhtAddress& id, int bucket_index, const NetworkAddress& from, int latency, UINT tick)
{
	ASSERT(bucket_index >= DHT_BUCKET_DISTANCE_BASE);

	DhtSpace::dht_node p;
	UINT node_index = FindNode(id);
	if(node_index<GetNodeCount() && GetNodeBucketIndex(node_index) == bucket_index)
	{	
		DhtSpace::dht_node& p = *_NodeIndex[node_index].node;
		if(p.NetAddress == from)
		{
			// quick state update, these update may be lost in the next iteration with a very small possibility					
			p.last_recv = tick;
			p.UpdateLatency(latency);
		}
		//else ignore messages from nodes with duplicated Id

		return true;
	}

	return false;
}

void DhtSpace::FinalizeUpdate(UINT tick, const DhtAddress& ownid)
{
	UINT	node_count = 0;
	UINT	latency_unk_count = 0;
	float	latency = 0.0f;
	for(UINT i=0;i<DHT_SPACE_SIZE-DHT_BUCKET_DISTANCE_BASE;i++)
	{
		node_count += _Buckets[i]._Used;
		for(UINT j=0;j<_Buckets[i]._Used;j++)
		{	
			if(_Buckets[i]._Nodes[j].latency_average >= 0)
				latency += _Buckets[i]._Nodes[j].latency_average;
			else
				latency_unk_count++;
		}
	}

	ASSERT(node_count == _TotalNodes);
	if(node_count > latency_unk_count)
		_OverallLatency = latency/(node_count - latency_unk_count);
	else
		_OverallLatency = DHT_SPACE_NODE_ACCEPTABLE_LATENCY/NET_TICK_UNIT_FLOAT;

	UINT last_unfilled = DHT_SPACE_SIZE-1;
	float good_latency_bar = GetGoodLatencyBar();
	for(UINT i=DHT_SPACE_SIZE-1;i>=DHT_BUCKET_DISTANCE_BASE;i--)
	{
		auto& bucket = GetBucket(i);
		bucket._BadCount = 0;
		if(bucket._Used)
		{
			for(UINT j=0;j<bucket._Used;j++)
			{	
				if(bucket._Nodes[j].IsReplacable(tick, good_latency_bar))
					bucket._BadCount++;
			}
		}
		else
		{	last_unfilled = i;
		}
	}
}

void DhtSpace::dht_node::Init(UINT timestamp, const Peer& node_info)
{
	*((Peer*)this) = node_info;
	discover_time = timestamp;
	last_recv = timestamp;
	latency_average = -1;
}



DhtSpace::dht_node& DhtSpace::dht_bucket::Append(const dht_node& p)
{
	dht_node& newp = Append();
	newp = p;
	return newp;
}

DhtSpace::dht_node& DhtSpace::dht_bucket::Append()
{
	ASSERT(_Used < DHT_BUCKET_SIZE);
	_Used++;
	return _Nodes[_Used - 1];
}


UINT DhtSpace::GetClosestNodes(const DhtAddress& target, UINT tick, _CollectedNode* pOut, UINT OutSize) const
{
	int closest = (int)rt::LowerBound<_NodeIndexGetKey>(_NodeIndex, _TotalNodes, target);

	int up = closest;
	UINT up_dist = DHT_DISTANCE_MAX + 1;
	for(;up<(int)_TotalNodes;up++)
		if(!_NodeIndex[up].node->IsZombie(tick))
		{	up_dist = DhtAddress::Distance(_NodeIndex[up].node->DhtAddress, target);
			break;
		}

	int down = closest-1;
	UINT down_dist = DHT_DISTANCE_MAX + 1;
	for(;down>=0;down--)
		if(!_NodeIndex[down].node->IsZombie(tick))
		{	down_dist = DhtAddress::Distance(_NodeIndex[down].node->DhtAddress, target);
			break;
		}

	UINT collected = 0;
	for(;collected<OutSize;collected++)
	{
		if(up_dist == down_dist && up_dist == DHT_DISTANCE_MAX + 1)break;
		if(	up_dist < down_dist || 
			(up_dist == down_dist && (collected&1))
		)
		{	// pick from up
			pOut[collected].node = *_NodeIndex[up].node;
			pOut[collected].distance = up_dist;
			pOut[collected].latency = _NodeIndex[up].node->latency_average;
			up++;
			up_dist = DHT_DISTANCE_MAX + 1;
			for(;up<(int)_TotalNodes;up++)
				if(!_NodeIndex[up].node->IsZombie(tick))
				{	up_dist = DhtAddress::Distance(_NodeIndex[up].node->DhtAddress, target);
					break;
				}
		}
		else
		{	// pick from up
			pOut[collected].node = *_NodeIndex[down].node;
			pOut[collected].distance = down_dist;
			pOut[collected].latency = _NodeIndex[down].node->latency_average;
			down--;
			down_dist = DHT_DISTANCE_MAX + 1;
			for(;down>=0;down--)
				if(!_NodeIndex[down].node->IsZombie(tick))
				{	down_dist = DhtAddress::Distance(_NodeIndex[down].node->DhtAddress, target);
					break;
				}
		}
	}

	return collected;
}

void DhtSpace::DiscoverNewNodes(MainlineDHT* dht, dht_node_discovered_queue& discovered_nodes, UINT tick)
{
	dht_node_discovered pd;
	float good_latency_bar = GetGoodLatencyBar();

	while(discovered_nodes.Pop(pd))
	{
		if(pd.bucket == -1)
		{
			pd.bucket = DhtAddress::Distance(dht->GetNodeId(), pd.nodeinfo.DhtAddress);
			if(pd.bucket < DHT_BUCKET_DISTANCE_BASE)continue;
		}

		ASSERT(pd.bucket >= DHT_BUCKET_DISTANCE_BASE);

		if(!pd.is_new)
		{	UpdateExisted(pd.nodeinfo.DhtAddress, pd.bucket, pd.nodeinfo.NetAddress, pd.latency, pd.timestamp);
			continue;
		}

		UINT pos = (UINT)rt::LowerBound<_NodeIndexGetKey>(_NodeIndex, _TotalNodes, pd.nodeinfo.DhtAddress);
		if(pos < _TotalNodes && _NodeIndex[pos].node->DhtAddress == pd.nodeinfo.DhtAddress)
		{
			if(pd.IsActualReceived())
			{
				dht_node& p = *_NodeIndex[pos].node;
				if(p.NetAddress == pd.nodeinfo.NetAddress)  // Existing Node, IP should match
				{
					// Race condition, but the error is acceptable
					p.last_recv = rt::max(p.last_recv, pd.timestamp);
					p.UpdateLatency(pd.latency);
				}
			}
			pd.bucket = -1;
		}
		else
		{	// New Peer
			if(pd.bucket>DHT_BUCKET_DISTANCE_BASE && GetBucket(pd.bucket-1).IsAcceptingNewNode())
				dht->_SendFindSelf(pd.nodeinfo.NetAddress);

			dht_bucket& bucket = GetBucket(pd.bucket);
			if(bucket._Used == DHT_BUCKET_SIZE)
			{
				int max_i = -1;
				UINT max_score = 0;
				for(UINT i=0;i<bucket._Used;i++)
				{	// search for worst node to be replaced
					dht_node& p = bucket._Nodes[i];
					ASSERT(p.DhtAddress != pd.nodeinfo.DhtAddress);
					if(	p.IsZombie(tick) || 
						(pd.IsActualReceived() && p.IsSlow(good_latency_bar) && pd.latency>=0 && pd.latency<good_latency_bar)
					)
					{	UINT score = p.UnheathyScore(tick, good_latency_bar);
						if(score > max_score)
						{	max_i = i;
							max_score = score;
						}
					}
				}
				if(max_i>=0)
				{	// replace with new node
					dht_node& bad_p = bucket._Nodes[max_i];
					// Update PeerIndex
					UINT remove_pos = (UINT)rt::BinarySearch<_NodeIndexGetKey>(_NodeIndex, _TotalNodes, bad_p.DhtAddress);
					ASSERT(pos <= _TotalNodes);
					//if(pos == _TotalNodes)pos--; // a corner case found in 1/10/2014, which ruin _NodeIndex
					if(remove_pos > pos)
					{	memmove(&_NodeIndex[pos+1], &_NodeIndex[pos], (remove_pos - pos)*sizeof(dht_node_index_entry));
					}
					else if(remove_pos < pos)
					{	pos--;
						memmove(&_NodeIndex[remove_pos], &_NodeIndex[remove_pos+1], (pos - remove_pos)*sizeof(dht_node_index_entry));
					}
					// else, no need to shift the index

					_NodeIndex[pos].bucket = pd.bucket;
					_NodeIndex[pos].offset = max_i;
					_NodeIndex[pos].node = &bad_p;

					bad_p.Init(pd.timestamp, pd.nodeinfo);

					ValidateNodeIndex();
					bad_p.UpdateLatency(pd.latency);

#ifdef OXD_NET_DEBUG_REPORT
					_LOGC('['<<pd.bucket<<']'<<' '<<tos(pd.nodeinfo.DhtAddress)<<' '<<tos(pd.nodeinfo.NetAddress)<<" LTNC:"<<pd.latency);
#endif
					pd.bucket = -1;
				}
			}
			else
			{	dht_node& newp = bucket.Append();
				newp.Init(pd.timestamp, pd.nodeinfo);
				if(pd.IsIntroduced())
				{	// make it trigger PING but not zombie
					newp.last_recv = tick - rt::min(tick, (DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT + DHT_SPACE_NODE_PING_BY_LASTRECV_TIMEOUT)/2);
				}
				else
				{	newp.UpdateLatency(pd.latency);
				}

				// Update PeerIndex
				memmove(&_NodeIndex[pos+1], &_NodeIndex[pos], (_TotalNodes - pos)*sizeof(dht_node_index_entry));

				_NodeIndex[pos].bucket = pd.bucket;
				_NodeIndex[pos].offset = bucket._Used-1;
				_NodeIndex[pos].node = &newp;

				_TotalNodes++;
				ValidateNodeIndex();
				
#ifdef OXD_NET_DEBUG_REPORT
				_LOGC('['<<pd.bucket<<']'<<' '<<tos(pd.nodeinfo.DhtAddress)<<' '<<tos(pd.nodeinfo.NetAddress)<<" LTNC:"<<pd.latency);
#endif
				pd.bucket = -1;
			}
		}
	}
}

void DhtSpace::GetStateReport(rt::String& out, UINT tick) const
{
    static const char LN = '\n';

	double bucket_space_size = 1.0;

	double network_size_sum = 0;
	UINT   network_size_count = 0;

	double network_size_avail_sum = 0;
	UINT   network_size_avail_count = 0;

	bool   network_size_stopped = false;

	int longterm = 0;
	int zombie = 0;
	int newp = 0;

	for(int i=DHT_SPACE_SIZE-1; i>=DHT_BUCKET_DISTANCE_BASE; i--, bucket_space_size*=2.0)
	{
		const DhtSpace::dht_bucket& bucket = GetBucket(i);

		if(bucket._Used)
		{
			float la = 0;
			float la_max = 0;
			int la_count = 0;

			for(UINT j=0;j<bucket._Used;j++)
			{	const DhtSpace::dht_node& p = bucket._Nodes[j];
				if(!p.IsZombie(tick))
				{	if(p.last_recv > 5*60*1000/NET_TICK_UNIT + p.discover_time)
						longterm++;
					else
						newp++;

					if(p.latency_average >=0)
					{	la += p.latency_average;
						la_max = rt::max(la_max, p.latency_average);
						la_count++;
					}
				}
				else zombie++;
			}

			double bucket_netsize = bucket_space_size*bucket._Used;
			if(!network_size_stopped)
			{
				network_size_sum += bucket_netsize;
				network_size_count ++;

				if(la_count)
				{	network_size_avail_sum += bucket_space_size*la_count;
					network_size_avail_count ++;
				}
			}

			if(la_count)
			{
				out +=	rt::SS("Bucket[") + rt::tos::Number(i).RightAlign(3,' ') + rt::SS("]:  ") + 
							rt::tos::Number(la_count).RightAlign(2,' ') + '/' + 
							rt::tos::Number(bucket._Used).LeftAlign(2,' ') + 
						rt::SS("   SZ:") + rt::tos::FileSize<true,true,' '>((ULONGLONG)bucket_netsize).LeftAlign(9,' ').TrimRight(1) + 
						rt::SS("   LTNC:") + (int)(NET_TICK_UNIT_FLOAT*la/la_count + 0.5f) + '/' + (int)(NET_TICK_UNIT_FLOAT*la_max + 0.5f) +
						LN;
			}
			else
			{
				out +=	rt::SS("Bucket[") + rt::tos::Number(i).RightAlign(3,' ') + rt::SS("]:  ") + 
							rt::tos::Number(0).RightAlign(2,' ') + '/' + 
							rt::tos::Number(bucket._Used).LeftAlign(2,' ') + 
						rt::SS("   SZ:") + rt::tos::FileSize<true,true,' '>((ULONGLONG)bucket_netsize).LeftAlign(9,' ').TrimRight(1) + LN;
			}
		}
		else
		{	if(i<DHT_SPACE_SIZE - 16)
				network_size_stopped = true;
		}
	}

	out += rt::SS("Nodes: ") + GetNodeCount() + rt::SS(" = ") + longterm + 'L' + ' ' + newp + 'N' + ' ' + zombie + 'Z';

	LONGLONG total_netsize = (LONGLONG)(network_size_sum/network_size_count + 0.5);
	LONGLONG total_avail_netsize = (LONGLONG)(network_size_avail_sum/network_size_avail_count + 0.5);

	if(network_size_avail_count)
	{
		out += rt::SS("\nNetwork Size:") + rt::tos::FileSize<true, true>(total_avail_netsize).TrimRight(1) + '/' + rt::tos::FileSize<true, true>(total_netsize).TrimRight(1);
	}
			
	out += rt::SS(", LNTC:") + (int)(GetOverallLatency()*NET_TICK_UNIT_FLOAT + 0.5f) + LN;
}

void DhtSpace::GetNetworkScale(ULONGLONG* entire_scale, UINT* connected_routing, UINT tick) const
{
	double bucket_space_size = 1.0;

	double network_size_avail_sum = 0;
	UINT   network_size_avail_count = 0;

	bool   network_size_stopped = false;

	int longterm = 0;
	int newp = 0;

	for(int i=DHT_SPACE_SIZE-1; i>=DHT_BUCKET_DISTANCE_BASE; i--, bucket_space_size*=2.0)
	{
		const DhtSpace::dht_bucket& bucket = GetBucket(i);

		if(bucket._Used)
		{
			float la = 0;
			float la_max = 0;
			int la_count = 0;

			for(UINT j=0;j<bucket._Used;j++)
			{	const DhtSpace::dht_node& p = bucket._Nodes[j];
				if(!p.IsZombie(tick))
				{	if(p.last_recv > 5*60*1000/NET_TICK_UNIT + p.discover_time)
						longterm++;
					else
						newp++;

					if(p.latency_average >=0)
					{	la += p.latency_average;
						la_max = rt::max(la_max, p.latency_average);
						la_count++;
					}
				}
			}

			double bucket_netsize = bucket_space_size*bucket._Used;
			if(!network_size_stopped && la_count)
			{
				network_size_avail_sum += bucket_space_size*la_count;
				network_size_avail_count ++;
			}
		}
		else
		{	network_size_stopped = true;
		}
	}

	if(entire_scale)*entire_scale = (ULONGLONG)(network_size_avail_sum/network_size_avail_count + 0.5);
	if(connected_routing)*connected_routing = longterm + newp;
}

void DhtSpace::GetState(NetworkState_DHT& ns, UINT tick) const
{
	double bucket_space_size = 1.0;

	double network_size_sum = 0;
	UINT   network_size_count = 0;

	double network_size_avail_sum = 0;
	UINT   network_size_avail_count = 0;

	bool   network_size_stopped = false;

	int longterm = 0;
	int zombie = 0;
	int newp = 0;

	rt::Zero(ns.DHT_Buckets);
	ns.DHT_DistanceBase = DHT_BUCKET_DISTANCE_BASE;

	for(int i=DHT_SPACE_SIZE-1; i>=DHT_BUCKET_DISTANCE_BASE; i--, bucket_space_size*=2.0)
	{
		const DhtSpace::dht_bucket& bucket = GetBucket(i);

		if(bucket._Used)
		{
			float la = 0;
			float la_max = 0;
			int la_count = 0;

			for(UINT j=0;j<bucket._Used;j++)
			{	const DhtSpace::dht_node& p = bucket._Nodes[j];
				if(!p.IsZombie(tick))
				{	if(p.last_recv > 5*60*1000/NET_TICK_UNIT + p.discover_time)
						longterm++;
					else
						newp++;

					if(p.latency_average >=0)
					{	la += p.latency_average;
						la_max = rt::max(la_max, p.latency_average);
						la_count++;
					}
				}
				else zombie++;
			}

			double bucket_netsize = bucket_space_size*bucket._Used;
			if(!network_size_stopped)
			{
				network_size_sum += bucket_netsize;
				network_size_count ++;

				if(la_count)
				{	network_size_avail_sum += bucket_space_size*la_count;
					network_size_avail_count ++;
				}
			}

			auto& b = ns.DHT_Buckets[i - DHT_BUCKET_DISTANCE_BASE];
			b.NodesReachable = la_count;
			b.NodesTotal = bucket._Used;
			if(la_count)
			{	b.Latency = (UINT)(la/la_count*NET_TICK_UNIT_FLOAT + 0.5f);
				b.LatencyMax = (UINT)(la_max*NET_TICK_UNIT_FLOAT + 0.5f);
			}
			else
			{	b.Latency = b.LatencyMax;
			}
		}
		else
		{	network_size_stopped = true;
		}
	}

	ns.DHT_NodeLongterm = longterm;
	ns.DHT_NodeNew = newp;
	ns.DHT_NodeZombie = zombie;

	if(network_size_count)
		ns.DHT_SpaceSize = (LONGLONG)(network_size_sum/network_size_count + 0.5);
	else
		ns.DHT_SpaceSize = 0;

	if(network_size_avail_count)
		ns.DHT_ReachableSpaceSize = (LONGLONG)(network_size_avail_sum/network_size_avail_count + 0.5);
	else
		ns.DHT_ReachableSpaceSize = 0;

	ns.DHT_Latency = (UINT)(GetOverallLatency()*NET_TICK_UNIT_FLOAT + 0.5f);
}

void DhtSpace::Rebuild(const DhtSpace& space, MainlineDHT& dht)
{
	space.ValidateNodeIndex();

	// copy to the next space and remove dead nodes
	Reset();
	int NodeRemoved[DHT_SPACE_SIZE-DHT_BUCKET_DISTANCE_BASE];
	rt::Zero(NodeRemoved);

	float high_latency_bar = space.GetHighLatencyBar();

	for(UINT i=0;i<space._TotalNodes;i++)
	{
		const dht_node_index_entry& e = space._NodeIndex[i];
		const dht_bucket& buck = space.GetBucket(e.bucket);

		ASSERT(e.bucket < DHT_SPACE_SIZE);
		ASSERT(e.bucket >= DHT_BUCKET_DISTANCE_BASE);
		ASSERT(e.offset < buck._Used);
		ASSERT(buck._Used <= DHT_BUCKET_SIZE);

		const dht_node& p = buck._Nodes[e.offset];
		ASSERT(&p == e.node);

		//ASSERT(dht.GetTick() >= p.last_recv);
		int last_recv_elapse = rt::max(0, (int32_t)dht.GetTick() - p.last_recv);

		if(	buck._Used - NodeRemoved[e.bucket-DHT_BUCKET_DISTANCE_BASE] < DHT_SPACE_NODE_SHORTAGE ||
			(	last_recv_elapse < DHT_SPACE_NODE_REMOVE_BY_LASTRECV_TIMEOUT &&
				p.latency_average < high_latency_bar
			)
		)
		{	dht_node_index_entry& e_next = _NodeIndex[_TotalNodes];
			e_next.bucket = e.bucket;
			e_next.offset = GetBucket(e.bucket)._Used;
			e_next.node = &GetBucket(e.bucket).Append(p);

			_TotalNodes++;

			if(last_recv_elapse >= DHT_SPACE_NODE_PING_BY_LASTRECV_TIMEOUT)
			{
				if(e.bucket>DHT_BUCKET_DISTANCE_BASE && space.GetBucket(e.bucket-1).IsNodeShortage())
				{
					dht._SendFindSelf(p.NetAddress);
				}
				else
					dht._SendPing(p.NetAddress);
			}
		}
		else
		{	//the node is not kept in the next space
			NodeRemoved[e.bucket-DHT_BUCKET_DISTANCE_BASE]++;
		}
	}

	ValidateNodeIndex();
}

void DhtSpace::UpdateBootstrapList(const rt::hash_set<rt::String, rt::String::hash_compare>& old_peers, UINT tick, DhtSpace::dht_bootstrap_ip_list& sort_list) const
{
	for(UINT i=0;i<DHT_SPACE_SIZE-DHT_BUCKET_DISTANCE_BASE;i++)
	{
		const dht_bucket& b = _Buckets[i];
		for(UINT i=0;i<b._Used;i++)
			if(!b._Nodes[i].IsZombie(tick) && b._Nodes[i].latency_average>=0)
			{	
				auto& c = sort_list.push_back();
				c.addr = b._Nodes[i].NetAddress;
				c.score = b._Nodes[i].latency_average + 300;
				if(old_peers.find(tos(c.addr)) != old_peers.end())
					c.score /= 2;
			}
	}
}

bool DhtSpace::IsMature(UINT tick) const
{
	UINT active_node_count = 0;
	for(UINT i=DHT_SPACE_SIZE - 1; i>=DHT_BUCKET_DISTANCE_BASE; i--)
	{
		const dht_bucket& b = _Buckets[i - DHT_BUCKET_DISTANCE_BASE];
		for(UINT i=0;i<b._Used;i++)
			if(!b._Nodes[i].IsZombie(tick) && b._Nodes[i].latency_average>=0)
			{	
				active_node_count++;
				if(active_node_count >= DHT_SPACE_EXPECTED_ACTIVE_NODES)
					return true;
			}
	}

	return false;
}

} // namespace upw
