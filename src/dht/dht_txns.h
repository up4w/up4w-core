#pragma once
#include "dht_tx_nodes.h"

namespace upw
{

class DhtTxRecentHosts
{
protected:
	MainlineDHT&		_DHT;
	typedef ext::fast_map<IPv4, int> t_InvolvedNodes;
	typedef ext::fast_map<IPv6, int> t_InvolvedNodesV6;
	t_InvolvedNodes		_RecentQueriedHosts;
	t_InvolvedNodesV6	_RecentQueriedHostsV6;
	UINT				_RecentQueriedHostsLimit = 1000;
	UINT				_RecentPeriod = 300;	// 30 sec

public:
	DhtTxRecentHosts(MainlineDHT& dht):_DHT(dht){}
	bool	IsQueryAllowed(const IPv4& ip, bool auto_insert = true)
			{	if(_RecentQueriedHosts.size() >= _RecentQueriedHostsLimit)return false;
				if(_RecentQueriedHosts.has(ip))return false;
				if(auto_insert)_RecentQueriedHosts[ip] = _DHT.GetTick();
				NET_DEBUG_LOG("ping: "<<tos(ip));
				return true;
			}
	bool	IsQueryAllowed(const IPv6& ip, bool auto_insert = true)
			{	if(_RecentQueriedHostsV6.size() >= _RecentQueriedHostsLimit)return false;
				if(_RecentQueriedHostsV6.has(ip))return false;
				if(auto_insert)_RecentQueriedHostsV6[ip] = _DHT.GetTick();
				NET_DEBUG_LOG("ping: "<<tos(ip));
				return true;
			}
	bool	IsQueryAllowed(const NetworkAddress& ip, bool auto_insert = true)
			{
				if(ip.IsIPv4())return IsQueryAllowed(ip.IPv4(), auto_insert);
				else if(ip.IsIPv6())return IsQueryAllowed(ip.IPv6(), auto_insert);
				return false;
			}
	void	AddQueried(const NetworkAddress& ip)
			{	
				NET_DEBUG_LOG("ping: "<<tos(ip));
				if(ip.IsIPv4())return AddQueried(ip.IPv4());
				else if(ip.IsIPv6())return AddQueried(ip.IPv6());
			}
	void	AddQueried(const IPv4& ip){ _RecentQueriedHosts[ip] = _DHT.GetTick(); }
	void	AddQueried(const IPv6& ip){ _RecentQueriedHostsV6[ip] = _DHT.GetTick(); }
	void	SetCapacityHint(UINT num);
	void	Empty();
	bool	IsFull() const;
	void	SetHardLimit(UINT limit){ _RecentQueriedHostsLimit = limit; }
	void	SetRecentPeriod(UINT msec){ _RecentPeriod = msec/NET_TICK_UNIT; }
	void	Iterate();
};

} // upw
