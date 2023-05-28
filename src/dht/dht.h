#pragma once

#include "../../externs/miniposix/essentials.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../netsvc_core.h"
#include "dht_base.h"
#include "dht_space.h"
#include "dht_message.h"

#include <deque>


namespace upw
{

class MainlineDHT;
class DhtTxFindNode;
class DhtTxJoinSwarm;
class DhtTxConnSwarm;

namespace _details
{

template<typename T>
class DhtTxns
{
	struct _Txns
	{	
		rt::BufferEx<T*>	IdMap;
		ext::fast_map_ptr_aliased_key<rt::PodRef<DhtAddress>, T>	AddrMap;
	};

	os::ThreadSafeMutable<_Txns>	_Txns;
public:
	void	Jsonify(rt::Json& json) const 
			{	json.Array();
				THREADSAFEMUTABLE_SCOPE(_Txns);
				auto& t = _Txns.GetImmutable();
				for(auto it : t.AddrMap)
				{
					it.second->Jsonify(json.ScopeAppendingElement());
				}
			}
	template<typename ... ARGS>
	T*		Create(MainlineDHT& dht, const DhtAddress& target, ARGS... args)
			{	auto* p = _New(T(target, dht, args...));
				{	THREADSAFEMUTABLE_UPDATE(_Txns, f);
					auto& old = f.GetUnmodified();
					if(old.AddrMap.get(target) == nullptr)
					{	f.ReadyModify(true);
						auto slot = old.IdMap.Find(nullptr);
						if(slot>=0)
						{	f->IdMap.SetSize(old.IdMap.GetSize());
						}
						else
						{	slot = old.IdMap.GetSize();
							f->IdMap.SetSize(slot + 1);					
						}
						old.IdMap.CopyTo(f->IdMap.Begin());
						p->_TX = (UINT)(slot + 1);
						f->IdMap[slot] = p;
						for(auto e : f->IdMap)
							if(e)f->AddrMap.set(e->GetTarget(), e);
						return p;
					}
				}
				_SafeDel(p);
				return nullptr;
			}
	void	Destroy(UINT tx)
			{	tx--;
				T* p = nullptr;
				{	THREADSAFEMUTABLE_UPDATE(_Txns, f);
					auto& old = f.GetUnmodified();
					if(old.IdMap.GetSize() <= tx)return;
					f.ReadyModify(true);
					f->IdMap.SetSize(old.IdMap.GetSize());
					old.IdMap.CopyTo(f->IdMap.Begin());
					p = f->IdMap[tx];
					f->IdMap[tx] = nullptr;
					f->AddrMap.erase(p->GetTarget());
				}
				
				if constexpr (rt::IsTypeSame<DhtTxJoinSwarm, T>::Result)
					if(p)p->Leave();

				_SafeDel_Delayed(p, 3000);
			}
	UINT	GetSize() const { THREADSAFEMUTABLE_SCOPE(_Txns); return (UINT)_Txns.GetImmutable().IdMap.GetSize(); }
	T*		Get(const DhtAddress& target) const { THREADSAFEMUTABLE_SCOPE(_Txns); return (T*)_Txns.GetImmutable().AddrMap.get(target); }
	T*		Get(UINT txid) const { THREADSAFEMUTABLE_SCOPE(_Txns); auto& txns = _Txns.GetImmutable().IdMap; return (txid>0 && txid<=txns.GetSize())?txns[txid-1]:nullptr; }
	void	Awaken() const
			{	THREADSAFEMUTABLE_SCOPE(_Txns);
				auto& txns = _Txns.GetImmutable().IdMap;
				for(auto p : txns)if(p)p->Awaken();
			}
	void	InitiatePeerAnnoucement() const
			{	THREADSAFEMUTABLE_SCOPE(_Txns);
				auto& txns = _Txns.GetImmutable().IdMap;
				for(auto p : txns)if(p)p->InitiatePeerAnnoucement();
			}
	bool	HasImmature() const
			{	THREADSAFEMUTABLE_SCOPE(_Txns);
				auto& txns = _Txns.GetImmutable().IdMap;
				for(auto p : txns)if(p && !p->IsMature())return true;
				return false;
			}
	void	Iterate() const
			{	THREADSAFEMUTABLE_SCOPE(_Txns);
				auto& txns = _Txns.GetImmutable().IdMap;
				for(auto p : txns)
				{	if(!p)continue;
					EnterCSBlock(*p);
					p->Iterate();
				}
			}
	void	OnReply(DhtTxReplyContext& rc) const
			{	ASSERT(rc.msg.fields_parsed&MSGFIELD_R_ID);
				auto* p = Get(rc.msg.reply_transId_tx);
				if(!p)return;
				rc.distance = DhtAddress::Distance(rc.msg.r_id, p->GetTarget());
				EnterCSBlock(*p);
				p->OnReply(rc);
			}
	void	GetStateReport(rt::String& out, UINT tick) const
			{
				THREADSAFEMUTABLE_SCOPE(_Txns);
				auto& txns = _Txns.GetImmutable().IdMap;
				for(UINT i=0;i<txns.GetSize();i++)
					if(txns[i])
					{
						txns[i]->GetStateReport(out, tick);
						out += '\n';
					}
			}
	~DhtTxns()
			{	THREADSAFEMUTABLE_LOCK(_Txns);
				if(!_Txns.IsEmpty())
				{
					for(auto p : _Txns.GetUnsafeMutable().IdMap)
						_SafeDel_ConstPtr(p);
					_Txns.Clear();
				}
			}
};
} // namespace _details


class MainlineDHT: public DhtMessageCompose
{
	friend class DhtSpace;

public:
	struct precomputed_messages
	{
		PacketBuf<9 + 3 + 1 + DHT_ADDRESS_SIZE + 16 + 4 + 4 + 9 + 7 + 11 + 1 + 9>	_PingMessage;
		PacketBuf<9 + 3 + 1 + DHT_ADDRESS_SIZE + 8 + 3 + 1 + DHT_ADDRESS_SIZE + 21 + 8 + 9 + 7 + 11 + 1 + 9 + 16> _FindMyselfMessage;
	};

protected:
#if defined(OXD_DUMP_DHT_MESSAGE)
	os::Timestamp			_log_Message_timer;
	os::File				_log_Message;
	void					_log_message_write(char tag, LPCSTR bencode, UINT codelen, const NetworkAddress& peer_addr);
#endif

protected:
	// State
	NetworkServiceCore*		_pNet;
	int						_BootstrapBoostCountDown;
	int						_BootstrapBoostCountDownIPv6;

	bool					_ResponseToFindQueries;
	bool					_ResponseToGetPeerQueries;
	bool					_ResponseToAnounnceQueries;

	// External IP/Port
	rt::TopWeightedValues<IPv4, 5>	_PublicIPv4;
	os::CriticalSection				_PublicIPv4CS;

	rt::TopWeightedValues<IPv6, 3>	_PublicIPv6;
	os::CriticalSection				_PublicIPv6CS;

#if defined(PLATFORM_DEBUG_BUILD)
	rt::TopWeightedValues<WORD, 10>	_PeerVersions;
	rt::TopWeightedValues<WORD, 10>	_PeerVersionsV6;
#endif
	// Peer's Versions: UT/97940 LT/34085 lt/835 Zo/624 TX/491 IL/409 MO/104, sampled 8/24/2014, Redmond, WA
	// Peer's Versions: UT/11208 LT/3909 lt/125 NS/122 Zo/71 TX/61 TR/59 MO/47 BD/6

	precomputed_messages	_PrecomputedMessages;
	void					_UpdatePrecomputedMessagesTransId();
	void					_PrecomputeMessages();

	os::ThreadSafeMutable<DhtSpace>		_DhtSpace;
	DhtSpace::dht_node_discovered_queue	_NodeDiscovered;  // thread-safe, lock-free

	os::ThreadSafeMutable<DhtSpace>		_DhtSpaceIPv6;
	DhtSpace::dht_node_discovered_queue	_NodeDiscoveredIPv6;  // thread-safe, lock-free

	rt::FrequencyDivision	_fd_SpaceUpdate = DHT_SPACE_UPDATE_INTERVAL_MIN;
	rt::FrequencyDivision	_fd_Bootstrap = DHT_BOOTSTRAP_INTERVAL;
	rt::FrequencyDivision	_fd_BootstrapBoost = DHT_BOOTSTRAP_BOOST_INTERVAL;
	rt::FrequencyDivision	_fd_BootstrapUpdate = DHT_BOOTSTRAP_UPDATE_INTERVAL;

	rt::FrequencyDivision	_fd_SpaceUpdateIPv6 = DHT_SPACE_UPDATE_INTERVAL_MIN;
	rt::FrequencyDivision	_fd_BootstrapIPv6 = DHT_BOOTSTRAP_INTERVAL;
	rt::FrequencyDivision	_fd_BootstrapBoostIPv6 = DHT_BOOTSTRAP_BOOST_INTERVAL;

protected:
	bool								_bHasImmatureTxn;
	_details::DhtTxns<DhtTxFindNode>	_FindingNodes;
	_details::DhtTxns<DhtTxJoinSwarm>	_JoinSwarms;
	_details::DhtTxns<DhtTxConnSwarm>	_ConnSwarms;

protected:
	// Helpers
	UINT	_GetBucketIndex(const DhtAddress& x){ return DhtAddress::Distance(_NodeId,x); } // return 0 ~ DHT_DISTANCE_MAX
	void	_LogMsg(const DhtMessageParse& msg, const NetworkAddress& from, UINT len);

	// Methods
	float	_GetSecondElapsed(UINT timestamp) const { return ((__int64)_Tick - (__int64)timestamp)*NET_TICK_UNIT_FLOAT/1000.0f; }
	UINT	_GetTime() const { return _Tick; }
	void	_SendPing(const NetworkAddress& to);
	void	_SendFindSelf(const NetworkAddress& to);
	void	_SendFindBucket(const DhtAddress& bucket, const NetworkAddress& to);
	void	_SendFindSelf(const rt::Buffer_Ref<NetworkAddress>& to);
	void	_SendFindSelfFromBulitInList();
	bool	_SendFindSelfFromFile(LPCSTR fn, NETADDR_TYPE type = NADDRT_NULL);
	void	_CollectDiscoveredNodes(const DhtMessageParse& msg, const NetworkAddress& from, float latency);
	void	_CollectDiscoveredNodesIPv6(const DhtMessageParse& msg, const NetworkAddress& from, float latency);
	UINT	_Iterate_UpdateDhtSpace();
	UINT	_Iterate_UpdateDhtSpaceIPv6();
	void	_OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx);
	void	_Bootstrap();
	void	_BootstrapIPv6();

public: 
	// rough statistics, will be slightly underestimated due to race condition
	struct _DhtStat
	{
		volatile ULONGLONG PingSent;
		volatile ULONGLONG FindNodeSent;
		volatile ULONGLONG GetPeerSent;
		volatile ULONGLONG AnnouncePeerSent;

		union
		{
			struct
			{
				volatile ULONGLONG PingReplyed;
				volatile ULONGLONG FindNodeReplyed;
				volatile ULONGLONG GetPeerReplyed;
				volatile ULONGLONG AnnouncePeerReplyed;
			};
			struct
			{	volatile ULONGLONG VerbReplyed[4];
			};
		};

		volatile ULONGLONG	RecvPing;
		volatile ULONGLONG	RecvFindNode;
		volatile ULONGLONG	RecvGetPeer;
		volatile ULONGLONG	RecvAnnouncePeer;
		volatile ULONGLONG	RecvError;
		volatile ULONGLONG	RecvDroppedPacket;
		volatile ULONGLONG	RecvCorruptedPacket;

		volatile __int64	TotalSentBytes;		// shifted by DHT_STATISTIC_SIZE_SHIFT
		volatile __int64	TotalRecvBytes;		// shifted by DHT_STATISTIC_SIZE_SHIFT
		volatile int		TotalSentPacket;
		volatile int		TotalRecvPacket;
	};

	_DhtStat state;
	const NetworkNodeDesc*	_pNodeDesc;
	rt::String				_StockBootstrapFilename;

public:
	MainlineDHT(NetworkServiceCore* datagram_net, const DhtAddress& ownid, const NetworkNodeDesc& nd);
	~MainlineDHT();

	void				SetStockBootstrapFile(const rt::String_Ref& fn){ _StockBootstrapFilename = fn; }
	NetworkServiceCore*	GetCore() const { return _pNet; }
	void				ForceRefresh();
    void                Awaken();
	void				ResetExternalIP();
	bool				IsMature() const { return IsMatureIPv4() ||  IsMatureIPv6(); }
	bool				IsMatureIPv4() const { THREADSAFEMUTABLE_SCOPE(_DhtSpace); return _DhtSpace.GetImmutable().IsMature(_Tick); }
	UINT				GetRoutingTableSize() const { THREADSAFEMUTABLE_SCOPE(_DhtSpace); return _DhtSpace.GetImmutable().GetNodeCount(); }
	void				GetNetworkScale(ULONGLONG* entire_scale, UINT* connected_routing) const { THREADSAFEMUTABLE_SCOPE(_DhtSpace); _DhtSpace.GetImmutable().GetNetworkScale(entire_scale, connected_routing, _Tick); }
	bool				IsMatureIPv6() const { THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6); return _DhtSpaceIPv6.GetImmutable().IsMature(_Tick); }
	UINT				GetRoutingTableSizeIPv6() const { THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6); return _DhtSpaceIPv6.GetImmutable().GetNodeCount(); }
	void				GetNetworkScaleIPv6(ULONGLONG* entire_scale, UINT* connected_routing) const { THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6); _DhtSpaceIPv6.GetImmutable().GetNetworkScale(entire_scale, connected_routing, _Tick); }

	bool				UpdateBootstrapList();
	void				GetStateReport(rt::String& report);
	void				SendBootstrapPing(const NetworkAddress& to){ _SendFindSelf(to); }

	UINT				StartFindingNode(const DhtAddress& target);	// return FindingId, nullptr for error
	void				StopFindingNode(UINT FindingId);

	UINT				StartJoinSwarm(const DhtAddress& target, UINT swarm_size = 8, const rt::String_Ref& boot_file = nullptr);	// return GettingId, nullptr for error
	UINT				StartJoinPrivateSwarm(const DhtAddress& target, const DhtAddress& private_secret, UINT swarm_size = 8, const DhtAddress* alt_node_id = nullptr, const rt::String_Ref& boot_file = nullptr);	// return GettingId, nullptr for error
	void				StopJoinSwarm(UINT SwarmId);
	void				InitiatePeerAnnoucement();

	UINT				StartConnSwarm(const DhtAddress& target, UINT swarm_size = 8, const rt::String_Ref& boot_file = nullptr);	// return GettingId, nullptr for error
	UINT				StartConnPrivateSwarm(const DhtAddress& target, const DhtAddress& private_secret, UINT swarm_size = 8, const DhtAddress* alt_node_id = nullptr, const rt::String_Ref& boot_file = nullptr);	// return GettingId, nullptr for error
	void				StopConnSwarm(UINT SwarmId);

	float				GetGoodLatencyBar() const { THREADSAFEMUTABLE_SCOPE(_DhtSpace); return _DhtSpace.GetImmutable().GetGoodLatencyBar(); }
	float				GetHighLatencyBar() const { THREADSAFEMUTABLE_SCOPE(_DhtSpace); return _DhtSpace.GetImmutable().GetHighLatencyBar(); }
	float				GetGoodLatencyBarIPv6() const { THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6); return _DhtSpaceIPv6.GetImmutable().GetGoodLatencyBar(); }
	float				GetHighLatencyBarIPv6() const { THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6); return _DhtSpaceIPv6.GetImmutable().GetHighLatencyBar(); }
	auto&				GetNodeDesc() const { return *_pNodeDesc; }

	bool				IsPublicAddressAvailable() const;
	const IPv4&			GetPublicAddress() const;

	bool				IsPublicAddressAvailableV6() const;
	const IPv6&			GetPublicAddressV6() const;

	void				JsonifySwarms(rt::Json& json) const;

	// Driven by Network
	void				OnTick(UINT tick);
	bool				SendPacket(Packet& data, const NetworkAddress& to, PACKET_SENDING_FLAG flag)
						{	os::AtomicAdd(data.GetLength(), &state.TotalSentBytes);
							os::AtomicIncrement(&state.TotalSentPacket);
						#if defined(OXD_DUMP_DHT_MESSAGE)
							_log_message_write('>', (LPCSTR)data.GetData(), data.GetLength(), to);
						#endif
							return _pNet->Send(data,to,flag);
						}

	void				GetState(NetworkState_DHT& ns) const;
	void				IterateUpdateDhtSpace() { _Iterate_UpdateDhtSpace(); };
	void				IterateUpdateDhtSpaceIPv6() { _Iterate_UpdateDhtSpaceIPv6(); };
    UINT				GetClosestNodes(const DhtAddress& target, DhtSpace::_CollectedNode* pOut, UINT OutSize) const { THREADSAFEMUTABLE_SCOPE(_DhtSpace); return _DhtSpace.GetImmutable().GetClosestNodes(target, GetTick(), pOut, OutSize); }
	UINT				GetClosestNodesIPv6(const DhtAddress& target, DhtSpace::_CollectedNode* pOut, UINT OutSize) const { THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6); return _DhtSpaceIPv6.GetImmutable().GetClosestNodes(target, GetTick(), pOut, OutSize); }

	auto*				GetSwarm(UINT swarm_id) const { return _JoinSwarms.Get(swarm_id); }
	bool				IsSwarmMature(UINT swarm_id) const;
	auto				GetSwarmPeers(UINT swarm_id) -> const PeerList&;
	auto				GetSwarmAddress(UINT swarm_id) const -> const DhtAddress&;
	void				SetSwarmPeerEventCallback(UINT swarm_id, DhtSwarmEventCallback cb, LPVOID cookie);

	auto*				GetConnSwarm(UINT swarm_id) const { return _ConnSwarms.Get(swarm_id); }
	const PeerList&		GetConnSwarmPeers(UINT swarm_id);
	bool				IsConnSwarmMature(UINT swarm_id) const;
	void				SetConnSwarmPeerEventCallback(UINT swarm_id, DhtSwarmEventCallback cb, LPVOID cookie);
	bool				InvitePeer(UINT swarm_id, const NetworkAddress& ip, bool conn_swarm);

	static void			SetMessageVersionTags(LPCSTR dht_ver, LPCSTR app_tag);
}; 


} // namespace upw
