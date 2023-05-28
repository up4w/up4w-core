#pragma once
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "dht_base.h"
#include "dht_message.h"
#include "dht_queue.h"
#include "dht.h"


namespace upw
{

class DhtTxn: public os::CriticalSection
{
	friend class MainlineDHT;
	template<typename T>
	friend class _details::DhtTxns;

protected:
	MainlineDHT&			_DHT;
	UINT					_TX;
	DhtAddress				_Target;

	struct node_tx: public DhtNodeBase
	{	UINT				distance;
	};
	DhtProximityQueue<node_tx, DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE>	_Found;
	DhtProximityQueue<node_tx, DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE>	_Potential;

	typedef ext::fast_map<NetworkAddress, UINT, NetworkAddress::hash_compare> t_InvolvedNodes;
	t_InvolvedNodes			_RecentQueriedHosts;		// NetAddress -> last_pinged
	UINT					_RecentQueriedHostsLimit;

public:
	DhtTxn(const DhtAddress&, MainlineDHT& dht);
	const DhtAddress&	GetTarget() const { return _Target; }
	UINT				GetTX() const { return _TX; }

	// Lock first before make any call below
	void	RefillNodeList();
	bool	AddNode(const DhtAddress& node, const NetworkAddress& from, UINT tick, int distance, float latency = -1.0f); // return true if find_node should be sent to it right now
	void	Iterate();
};

template<typename t_Derived>
class DhtTxnBase: public DhtTxn
{
protected:
	void _SendContactMessage(const NetworkAddress& to, bool no_discover, PACKET_SENDING_FLAG flag)
	{
		PacketBuf<> buf;
		if(no_discover)
		{
			DhtTxn::_DHT.state.PingSent++;
			const IPv6& na = DhtTxn::_DHT.IsPublicAddressAvailableV6()?DhtTxn::_DHT.GetPublicAddressV6():IPv6::Zero();
			buf.Commit(DhtTxn::_DHT.ComposeQueryPing(buf.Claim(), buf.SIZE, na, t_Derived::TX_TYPE, DhtTxn::GetTX()));
			//_LOG_WARNING("PING: "<<tos(to));
		}
		else
		{
			buf.Commit(((t_Derived*)this)->ComposeDiscoveryMessage(buf.Claim(), buf.SIZE));
			//if(to.Type() == NADDRT_IPV4 && (unsigned char)to.IPv4().IP == 95)
			//	_LOG_WARNING("DISCOVERY: "<<tos(to));
		}
		ASSERT(buf.GetLength());
		DhtTxn::_DHT.SendPacket(buf, to, PSF_DROPABLE|flag);
	}
	bool _IsMature() const { return ((t_Derived*)this)->IsMature(); }

public:
	void	OnReply(const DhtTxReplyContext& rc)
	{
#ifdef OXD_NET_DEBUG_REPORT
		_LOGC("TX["<<_TX<<"] Reply "<<tos(msg.r_id)<<' '<<distance<<' '<<tos(from)<<" TTNC:"<<((int)tick - (int)msg.reply_transId_tick));
#endif
		auto& msg = rc.msg;

		if(_IsMature())
		{
			if(t_Derived::TX_TYPE == RQTAG_TXTYPE_FINDNODE)
			{	auto& node = _Found[0];
				if(node.distance == 0 && t_Derived::TX_TYPE == RQTAG_TXTYPE_FINDNODE && rc.recvctx->RecvFrom == node.NetAddress && node.DhtAddress == msg.r_id)
					node.last_recv = rc.tick;
			}
		}
		else
		{
			AddNode(rc.msg.r_id, rc.recvctx->RecvFrom, rc.tick, rc.distance, rc.GetLatency());

			if(msg.fields_parsed&MSGFIELD_NODES)
			{
				// add introduced nodes
				int src_distance = DhtAddress::Distance(GetTarget(), msg.r_id);
				for(UINT i=0;i<msg.nodes_size;i++)
				{
					const DhtMessageParse::dht_compact_node& n = msg.nodes[i];
					int distance = DhtAddress::Distance(GetTarget(), n.DhtAddress);
					NetworkAddress node_ip(n.NetAddress);

#ifdef OXD_NET_DEBUG_REPORT
					_LOGC("TX["<<GetTX()<<"] FINDNODE NODE "<<tos(n.DhtAddress)<<' '<<distance<<' '<<tos(node_ip));
#endif
					bool findnode_boost = t_Derived::TX_TYPE == RQTAG_TXTYPE_FINDNODE && distance == 0;
					if(	(AddNode(n.DhtAddress, node_ip, rc.tick, distance, -1.0f) || findnode_boost)
						&& _RecentQueriedHosts.find(node_ip) == _RecentQueriedHosts.end()
					)
					{	_RecentQueriedHosts.insert(std::make_pair(node_ip, rc.tick));
						_SendContactMessage(node_ip, _IsMature() || findnode_boost, PSF_DROPABLE);
					}
				}
			}
		}
	}
	DhtTxnBase(const DhtAddress& target, MainlineDHT& dht):DhtTxn(target, dht){}

public:
	// Lock first before make any call below
	void Iterate()
	{
		UINT tick = DhtTxn::_DHT.GetTick();
		if(_IsMature())
		{
			if(t_Derived::TX_TYPE == RQTAG_TXTYPE_FINDNODE)
			{
				auto& node = _Found[0];
				if(	node.distance == 0)
				{
					if(node.last_sent > node.last_recv)
					{	// the node may gone
						if(tick - node.last_recv > node.latency_average*DHT_TRANSCATION_NODE_GONE_LATENCY_MULTIPLIER + 5000/NET_TICK_UNIT_FLOAT)
						{	_Potential.AddNew(node.DhtAddress, node.NetAddress, tick, 0, -1);
							_Found.Remove(0);
						}
						else if(tick - node.last_recv > node.latency_average*DHT_TRANSCATION_NODE_GONE_LATENCY_MULTIPLIER)
						{	_SendContactMessage(node.NetAddress, true, PSF_DROPABLE);
						}
					}
					else if((tick - node.last_recv) > (UINT)rt::max((int)DHT_TRANSCATION_PING_INTERVAL, (int)(9*(((int)DHT_TRANSCATION_NODE_REMOVE_BY_LASTRECV_TIMEOUT) - node.latency_average*2)/10 + 0.5)) &&
							(tick - node.last_sent) > DHT_TRANSCATION_PING_INTERVAL
					)
					{	_SendContactMessage(node.NetAddress, true, PSF_DROPABLE);
						node.last_sent = tick;
					}
				}
			}
		}
		else
		{
			if(DhtTxn::_Potential.GetSize() < 2 && DhtTxn::_Found.GetSize() == 0)
				DhtTxn::RefillNodeList();

			DhtTxn::Iterate();

			{	// detect node gone and send query
				int tick_ping_thres = rt::max(0, ((int)tick) - (int)DHT_TRANSCATION_PING_INTERVAL);
				int tick_remove_thres = rt::max(0, ((int)tick) - (int)DHT_TRANSCATION_NODE_REMOVE_BY_LASTRECV_TIMEOUT);

				{	int open = 0;
					for(UINT i=0;i<_Potential.GetSize();i++)
					{
						auto& p = DhtTxn::_Potential[i];
						bool findnode_boost = t_Derived::TX_TYPE == RQTAG_TXTYPE_FINDNODE && p.distance == 0;
						if(findnode_boost || p.discover_time > tick_remove_thres) // && p.distance<=(UINT)_Found.DistanceMax())
						{	
							if(open != i)DhtTxn::_Potential[open] = p;
							if(p.last_sent < tick_ping_thres)
							{
								auto& node = DhtTxn::_Potential[open];
								_RecentQueriedHosts.insert(std::make_pair(node.NetAddress, tick));
								_SendContactMessage(node.NetAddress, _IsMature() || findnode_boost, PSF_DROPABLE);
								node.last_sent = tick;
							}
							open++;
						}
					}
					_Potential.SetSize(open);
				}

				{	int open = 0;
					for(UINT i=0;i<_Found.GetSize();i++)
					{	
						auto& p = _Found[i];
						if(p.last_recv > tick_remove_thres)
						{
							if(open != i)_Found[open] = p;
							if(p.last_sent < tick_ping_thres)
							{
								auto& node = DhtTxn::_Found[open];
								_RecentQueriedHosts.insert(std::make_pair(node.NetAddress, tick));
								_SendContactMessage(node.NetAddress, _IsMature(), PSF_DROPABLE);
								node.last_sent = tick;
							}
							open++;
						}
						else
						{	// degrade to potential 
							_Potential.Add(p.DhtAddress, p.NetAddress, tick, p.distance, -1);
						}
					}
					_Found.SetSize(open);
				}
			}
		}
	}

	void	KickOff(){ RefillNodeList(); ((t_Derived*)this)->Iterate(); }
};


class DhtTxFindNode: public DhtTxnBase<DhtTxFindNode>
{
public:
	static const UINT TX_TYPE = RQTAG_TXTYPE_FINDNODE;

public:
	DhtTxFindNode(const DhtAddress& target, MainlineDHT& dht)
		:DhtTxnBase<DhtTxFindNode>(target, dht){}
	
	bool	IsMature() const { return _Found.DistanceMin() == 0; }
	int		ComposeDiscoveryMessage(LPSTR buf, int buf_size)
			{	_DHT.state.FindNodeSent++;
				return _DHT.ComposeQueryFindNode(buf, buf_size, GetTarget(), RQTAG_TXTYPE_FINDNODE, GetTX());
			}

	void	GetStateReport(rt::String& out, UINT tick) const;
};


} // upw
