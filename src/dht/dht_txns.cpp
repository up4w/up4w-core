#include "dht_txns.h"

namespace upw
{

void DhtTxRecentHosts::SetCapacityHint(UINT num)
{	
	if(_RecentQueriedHosts.size()*3 < num)
		_RecentQueriedHosts.rehash(num);

	if(_RecentQueriedHostsV6.size()*3 < num)
		_RecentQueriedHostsV6.rehash(num);
}

void DhtTxRecentHosts::Empty()
{
	_RecentQueriedHosts.clear();
	_RecentQueriedHostsV6.clear();
}

void DhtTxRecentHosts::Iterate()
{
	UINT t = _DHT.GetTick();
	int deadline = ((int)t) - _RecentPeriod;

	for(auto it = _RecentQueriedHosts.begin(); it != _RecentQueriedHosts.end(); it++)
		if(it->second < deadline)_RecentQueriedHosts.erase(it);

	for(auto it = _RecentQueriedHostsV6.begin(); it != _RecentQueriedHostsV6.end(); it++)
		if(it->second < deadline)_RecentQueriedHostsV6.erase(it);
}

bool DhtTxRecentHosts::IsFull() const
{
	return _RecentQueriedHosts.size() >= _RecentQueriedHostsLimit || _RecentQueriedHostsV6.size() >= _RecentQueriedHostsLimit;
}

} //upw