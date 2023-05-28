#include "dht_tx_nodes.h"

namespace upw
{


DhtTxn::DhtTxn(const DhtAddress& target, MainlineDHT& dht)
	:_DHT(dht)
{
	_TX = 0; // will be assigned by DhtTxns::Create
	_Target = target;
	
	_RecentQueriedHosts.rehash(2048);
}

void DhtTxn::RefillNodeList()
{
	ASSERT(IsLockedByCurrentThread());

	DhtSpace::_CollectedNode	nodes[DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE];
	UINT n = _DHT.GetClosestNodes(_Target, nodes, DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE);

	for(UINT i=0;i<n;i++)
		AddNode(nodes[i].node.DhtAddress, nodes[i].node.NetAddress, _DHT.GetTick(), nodes[i].distance, nodes[i].latency);

	for(UINT i=0;i<_Found.GetSize();i++)_Found[i].last_sent = 0;
	for(UINT i=0;i<_Potential.GetSize();i++)_Potential[i].last_sent = 0;
}

bool DhtTxn::AddNode(const DhtAddress& DhtAddress, const NetworkAddress& from, UINT tick, int distance, float latency)
{
	ASSERT(IsLockedByCurrentThread());

	bool send_findnode = false;
	if(latency>= -rt::TypeTraits<float>::Epsilon())
	{	// add to nodes
		if(!_Found.IsFull() || distance <= _Found.DistanceMax())
			if(_Found.Add(DhtAddress, from, tick, distance, latency) == TXQ_ADD_OK)
			{	
#ifdef OXD_NET_DEBUG_REPORT
				_LOGC("TX-Fnd: "<<tos(DhtAddress)<<' '<<distance<<' '<<tos(from));
#endif
				_Potential.Remove(from);
				send_findnode = true;
			}
	}
	else
	{
		if(_Found.Find(DhtAddress, from)>=0)
			return false; // already found

		if(!_Potential.IsFull() || distance <= _Potential.DistanceMax())
			if(_Potential.Add(DhtAddress, from, tick, distance, latency) != TXQ_DUPLICATION)
			{	
#ifdef OXD_NET_DEBUG_REPORT
				_LOGC("TX-Add: "<<tos(DhtAddress)<<' '<<distance<<' '<<tos(from));
#endif
				send_findnode = true;
			}
	}

	return send_findnode;
}


void DhtTxn::Iterate()
{
	ASSERT(IsLockedByCurrentThread());
	ASSERT(_TX>0 && _TX<0xffff);

	{	// forget some hosts
		UINT thres = rt::max(0, ((int)_DHT.GetTick()) - (int)DHT_TRANSCATION_PING_INTERVAL - (int)DHT_TRANSCATION_ITERATE_INTERVAL);
		for(auto it = _RecentQueriedHosts.begin(); it != _RecentQueriedHosts.end(); it++)
			if(it->second < thres)
				_RecentQueriedHosts.erase(it);
	}
}

void DhtTxFindNode::GetStateReport(rt::String& out, UINT tick) const
{
	EnterCSBlock(*this);

	out +=	tos(GetTarget()) + ':' + '\n' + 
			_Found.GetSize() + rt::SS("F/") + _Found.DistanceMin() + "d " + 
			_Potential.GetSize() + rt::SS("P/") + _Potential.DistanceMin() + 'd';

	if(IsMature())
	{	out += rt::SS(" F/") + tos(_Found[0].NetAddress) + " LTNC:" + _Found[0].latency_average + '\n';
	}
	else
	{	if(_Potential.GetSize() && _Potential[0].distance == 0)
			out += rt::SS(" P/") + tos(_Potential[0].NetAddress);

		out += rt::SS(" H=") + (UINT)_RecentQueriedHosts.size() + '\n';
	}
}

} // upw
