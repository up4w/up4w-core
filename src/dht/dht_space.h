#pragma once

#include "dht_base.h"
#include "dht_message.h"
#include "../../externs/miniposix/core/ext/concurrentqueue/async_queue.h"


namespace upw
{

class DhtSpace
{
public:
	struct dht_node: public DhtNodeBase
	{
		void	Init(UINT timestamp, const Peer& peer_info);
		bool	IsZombie(UINT tick) const { return tick > last_recv + DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT; }
		bool	IsReplacable(UINT tick, float good_lantency_bar) const { return IsZombie(tick) || IsSlow(good_lantency_bar); }
		UINT	UnheathyScore(UINT tick, float good_lantency_bar) const 
		{	int time_elapse = tick - last_recv;
			return time_elapse>DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT?time_elapse*1000:0 + 
				   (UINT)(NET_TICK_UNIT_FLOAT*(latency_average>good_lantency_bar?latency_average:0))/10;
		}
	};
	struct dht_bucket
	{
		dht_node		_Nodes[DHT_BUCKET_SIZE];
		UINT			_Used;
		UINT			_BadCount;	// # nodes that trigger DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT or DHT_SPACE_NODE_REMOVE_BY_HIGH_LATENCY_MULTIPLIER

		dht_bucket(){ rt::Zero(*this); }
		dht_node&		Append(const dht_node& p);
		dht_node&		Append();
		bool			IsAcceptingNewNode() const { return _BadCount || _Used<DHT_BUCKET_SIZE; }
		bool			IsNodeShortage() const { return (_Used - _BadCount) < DHT_BUCKET_SIZE/2; }
	};
	struct dht_node_discovered
	{
		Peer			nodeinfo;
		int				bucket;
		int				latency;	// sec
		int				timestamp;  // tick
		bool			is_new;
		bool			IsIntroduced() const { return latency < 0; }
		bool			IsActualReceived() const { return latency >= 0; }
	};
	typedef ext::AsyncDataQueue<DhtSpace::dht_node_discovered, false> dht_node_discovered_queue;
	struct dht_bootstrap_ip
	{	NetworkAddress	addr;
		float					score;
		bool operator < (const dht_bootstrap_ip& x) const { return score < x.score; }
	};
	using dht_bootstrap_ip_list = rt::BufferEx<DhtSpace::dht_bootstrap_ip>;
protected:
	struct dht_node_index_entry
	{
		dht_node*		node;
		WORD			bucket;
		WORD			offset;
		bool operator <(const dht_node_index_entry& x) const { return node->DhtAddress < node->DhtAddress; }
	};
	struct _NodeIndexGetKey
	{	static const DhtAddress& Key(const dht_node_index_entry& e){ return e.node->DhtAddress; }
	};
	dht_bucket				_Buckets[DHT_SPACE_SIZE-DHT_BUCKET_DISTANCE_BASE];
	dht_node_index_entry	_NodeIndex[DHT_BUCKET_SIZE*(DHT_SPACE_SIZE-DHT_BUCKET_DISTANCE_BASE)];
	UINT					_TotalNodes;

	float					_OverallLatency;
public:
	DhtSpace(){ Reset(); }
	void	Reset(){  rt::Zero(this, sizeof(DhtSpace)); }
	float	GetHighLatencyBar() const;
	float	GetGoodLatencyBar() const;
	void	ValidateNodeIndex() const;
	UINT	GetNodeCount() const { return _TotalNodes; }
	bool	IsMature(UINT tick) const;
	float	GetOverallLatency() const { return _OverallLatency; }

	const dht_bucket&	GetBucket(UINT i) const { ASSERT(i>=DHT_BUCKET_DISTANCE_BASE); return _Buckets[i-DHT_BUCKET_DISTANCE_BASE]; }
	dht_bucket&			GetBucket(UINT i){ ASSERT(i>=DHT_BUCKET_DISTANCE_BASE); return _Buckets[i-DHT_BUCKET_DISTANCE_BASE]; }
	const dht_node&		GetNode(UINT i) const { return *_NodeIndex[i].node; }

	UINT		FindNode(const DhtAddress& id) const { return (UINT)rt::BinarySearch<_NodeIndexGetKey>(_NodeIndex, _TotalNodes, id); }
	UINT		GetNodeBucketIndex(UINT i) const { return _NodeIndex[i].bucket; }
	UINT		GetNodeOffsetInBucket(UINT i) const { return _NodeIndex[i].offset; }

	struct _CollectedNode
	{	Peer	node;
		UINT	distance;
		float	latency;
	};
	UINT		GetClosestNodes(const DhtAddress& target, UINT tick, _CollectedNode* pOut, UINT OutSize) const; // sorted with acsend distance
	void		Rebuild(const DhtSpace& space, MainlineDHT& dht);
	void		FinalizeUpdate(UINT tick, const DhtAddress& ownid);
	void		DiscoverNewNodes(MainlineDHT* dht, dht_node_discovered_queue& discovered_nodes, UINT tick);
	bool		UpdateExisted(const DhtAddress& id, int bucket_index, const NetworkAddress& from, int latency, UINT tick); // true if an existed node is updated
	void		UpdateBootstrapList(const rt::hash_set<rt::String, rt::String::hash_compare>& list, UINT tick, DhtSpace::dht_bootstrap_ip_list& sort_list) const;
	void		GetStateReport(rt::String& out, UINT tick) const;
	void		GetState(NetworkState_DHT& ns, UINT tick) const;
	void		GetNetworkScale(ULONGLONG* entire_scale, UINT* connected_routing, UINT tick) const;
};

} // namespace upw
