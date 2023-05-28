#pragma once

#include "dht_base.h"

namespace upw
{

template<typename t_Node, UINT t_NodeListSize = 1>
struct DhtNodeQueue
{	
protected:
	UINT		_Len;
	UINT		_Capacity;
	t_Node		_Nodes[t_NodeListSize];

public:
	static DhtNodeQueue* Create(UINT NodeListSize)
	{	auto* ret = (DhtNodeQueue*)_Malloc32AL(BYTE, sizeof(t_Node)*NodeListSize + sizeof(UINT)*2);
		new (ret) DhtNodeQueue();
		ret->_Capacity = NodeListSize;
		return ret;
	}

	static void Destroy(LPVOID p){ _SafeFree32AL(p); }

	DhtNodeQueue(){ _Len = 0; _Capacity = t_NodeListSize; }
	UINT	GetSize() const { return _Len; }
	bool	IsFull() const { return _Len == _Capacity; }
	void	SetSize(UINT sz){ ASSERT(sz<=_Capacity); _Len = sz; } 
	UINT	GetCapacity() const { return _Capacity; }

	t_Node& operator		[](UINT index){ ASSERT(index < _Len); return _Nodes[index]; }
	const t_Node& operator	[](UINT index) const { ASSERT(index < _Len); return _Nodes[index]; }

	int		Find(const DhtAddress& dht_addr, const NetworkAddress& net_addr) // linear search
			{	for(int i=0;i<(int)_Len;i++)
					if(_Nodes[i].NetAddress == net_addr && _Nodes[i].DhtAddress == dht_addr)
						return i;
				return -1;
			}
};

template<typename t_Peer, UINT t_NodeListSize = 1>
struct DhtLatencyQueue: public DhtNodeQueue<t_Peer, t_NodeListSize> // sort by latency
{
	typedef DhtNodeQueue<t_Peer, t_NodeListSize> _SC;

	static DhtLatencyQueue* Create(UINT Capacity){ return (DhtLatencyQueue*)_SC::Create(Capacity); }

	int AddNew(const DhtAddress& dht_addr, const NetworkAddress& net_addr, UINT tick, float latency)  // return position if added, otherwise -1
	{
		float l = latency;
		if(latency<0)l = 10000/NET_TICK_UNIT_FLOAT;

		int i = _SC::_Len-1;
		for(;i>=0;i--)
		{
			if(l<(int)_SC::_Nodes[i].latency_average)continue;

			// insert to i+1
			i++;
			if(_SC::_Len < _SC::_Capacity)_SC::_Len++;
			if(i == _SC::_Len)
				return -1; // buffer full

			memmove(&_SC::_Nodes[i+1], &_SC::_Nodes[i], (_SC::_Len-i-1)*sizeof(t_Peer));
			break;
		}
		if(i < 0)
		{	ASSERT(i==-1);
			if(_SC::_Len < _SC::_Capacity)_SC::_Len++;
			memmove(&_SC::_Nodes[1], &_SC::_Nodes[0], (_SC::_Len-1)*sizeof(t_Peer));
			i=0;
		}

		auto& p = _SC::_Nodes[i];
		p.dht_addr = dht_addr;
		p.net_addr = net_addr;
		p.last_sent = tick;
		p.discover_time = tick;
		p.latency_average = latency;
		if(latency > -rt::TypeTraits<float>::Epsilon())
		{
			p.last_recv = tick;
		}
		else
		{	p.last_recv = tick - DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT - 1;
		}

		return i;
	}
};

enum _tagTXQueueAddRet
{
	TXQ_ADD_OK = 0,
	TXQ_DUPLICATION,	// not added due to existing peer/node
	TXQ_FULL			// not added due to buffer full
};

template<typename t_Node, UINT t_NodeListSize = 1>
struct DhtProximityQueue: public DhtNodeQueue<t_Node, t_NodeListSize> // sort by distance
{
	typedef DhtNodeQueue<t_Node, t_NodeListSize> _SC;

	int			DistanceMax() const { return _SC::_Len==0?DHT_DISTANCE_MAX:_SC::_Nodes[_SC::_Len-1].distance; }
	int			DistanceMin() const { return _SC::_Len==0?DHT_DISTANCE_MAX:_SC::_Nodes[0].distance; }

	static DhtProximityQueue* Create(UINT Capacity){ return (DhtProximityQueue*)_SC::Create(Capacity); }

	int AddNew(const DhtAddress& dht_addr, const NetworkAddress& net_addr, UINT tick, int distance, float latency)  // return position if added, otherwise -1
	{
		Validate();
		int i = _SC::_Len-1;
		for(;i>=0;i--)
		{
			if(distance<(int)_SC::_Nodes[i].distance)continue;

			// insert to i+1
			i++;
			if(_SC::_Len < _SC::_Capacity)_SC::_Len++;
			if(i == _SC::_Len)
				return -1; // buffer full

			memmove(&_SC::_Nodes[i+1], &_SC::_Nodes[i], (_SC::_Len-i-1)*sizeof(t_Node));
			break;
		}
		if(i < 0)
		{	ASSERT(i==-1);
			if(_SC::_Len < _SC::_Capacity)_SC::_Len++;
			memmove(&_SC::_Nodes[1], &_SC::_Nodes[0], (_SC::_Len-1)*sizeof(t_Node));
			i=0;
		}

		t_Node& p = _SC::_Nodes[i];
		p.DhtAddress = dht_addr;
		p.NetAddress = net_addr;
		p.distance = distance;
		p.last_sent = tick;
		p.discover_time = tick;
		p.latency_average = latency;
		if(latency > -rt::TypeTraits<float>::Epsilon())
		{
			p.last_recv = tick;
		}
		else
		{	p.last_recv = tick - DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT - 1;
		}

		Validate();
		return i;
	}

	DWORD Add(const DhtAddress& dht_addr, const NetworkAddress& net_addr, UINT tick, int distance, float latency)  // return _tagTXQueueAddRet
	{
		Validate();
		int i = _SC::_Len-1;
		for(;i>=0;i--)
		{
			if(distance<(int)_SC::_Nodes[i].distance)continue;
			if(distance == _SC::_Nodes[i].distance)
			{	if(_SC::_Nodes[i].DhtAddress == dht_addr && _SC::_Nodes[i].NetAddress == net_addr)
				{	// existed node
					_SC::_Nodes[i].last_recv = tick;
					_SC::_Nodes[i].UpdateLatency(latency);
					Validate();
					return TXQ_DUPLICATION;
				}
				continue;
			}

			// insert to i+1
			i++;
			if(_SC::_Len < _SC::_Capacity)_SC::_Len++;
			if(i == _SC::_Len)
				return TXQ_FULL; // buffer full

			memmove(&_SC::_Nodes[i+1], &_SC::_Nodes[i], (_SC::_Len-i-1)*sizeof(t_Node));
			break;
		}
		if(i < 0)
		{	ASSERT(i==-1);
			if(_SC::_Len < _SC::_Capacity)_SC::_Len++;
			memmove(&_SC::_Nodes[1], &_SC::_Nodes[0], (_SC::_Len-1)*sizeof(t_Node));
			i=0;
		}

		t_Node& p = _SC::_Nodes[i];
		p.DhtAddress = dht_addr;
		p.NetAddress = net_addr;
		p.distance = distance;
		p.last_sent = tick;
		p.discover_time = tick;
		p.latency_average = latency;
		if(latency > -rt::TypeTraits<float>::Epsilon())
		{
			p.last_recv = tick;
		}
		else
		{	p.last_recv = tick - DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT - 1;
		}

		Validate();
		return TXQ_ADD_OK;
	}

	void Remove(const NetworkAddress& net_addr, int distance = -1)
	{
		Validate();
		if(distance >= 0)
		{	for(UINT i=0;i<_SC::_Len;i++)
				if(distance == _SC::_Nodes[i].distance && _SC::_Nodes[i].NetAddress == net_addr)
				{
					_SC::_Len--;
					memmove(&_SC::_Nodes[i], &_SC::_Nodes[i+1], (_SC::_Len - i)*sizeof(t_Node));

					Validate();
					break;
				}
		}
		else
		{	for(UINT i=0;i<_SC::_Len;i++)
				if(_SC::_Nodes[i].NetAddress == net_addr)
				{
					_SC::_Len--;
					memmove(&_SC::_Nodes[i], &_SC::_Nodes[i+1], (_SC::_Len - i)*sizeof(t_Node));

					Validate();
					break;
				}
		}
	}

	void Remove(UINT i)
	{
		ASSERT(i<_SC::_Len);
		_SC::_Len--;
		memmove(&_SC::_Nodes[i], &_SC::_Nodes[i+1], (_SC::_Len - i)*sizeof(t_Node));
	}

	void Validate() const
	{
#ifdef PLATFORM_DEBUG_BUILD
		for(UINT i=1;i<_SC::_Len;i++)
		{	ASSERT(_SC::_Nodes[i].distance>=_SC::_Nodes[i-1].distance);
		}
#endif
	}

};



} // namespace upw
