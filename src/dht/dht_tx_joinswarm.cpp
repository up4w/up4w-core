#include "../../externs/miniposix/core/ext/ipp/ipp_core.h"
#include "../netsvc_core.h"
#include "dht.h"
#include "dht_tx_joinswarm.h"

namespace upw
{

DhtTxJoinSwarm::DhtTxJoinSwarm(const DhtAddress& target, MainlineDHT& dht, UINT expected_num, const DhtAddress* nodeid, DWORD app, const DhtAddress* private_secret, const rt::String_Ref& boot_file)
	:DhtTxSwarm(target,dht,expected_num,nodeid,app,private_secret,boot_file)
{
	_TX_TYPE = TX_TYPE;

	if(_DHT.GetCore()->IsDataServiceSuspended())
		_bActiveAnnouncementEndTime = os::Timestamp::Get();
	else
		InitiatePeerAnnoucement();

	_AnnounceToken = ipp::crc64((LPCBYTE)&target, DHT_ADDRESS_SIZE, (ULONGLONG)this);
}

void DhtTxJoinSwarm::OnReply(const DhtTxReplyContext& rc)
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
				(rc.recvctx->SendingFlag&PSF_IP_RESTRICTED_VERIFIED) == 0
			)
	)
	{	// ping with sec packet, again
		_SendContactMessage(rc.recvctx->RecvFrom, true, in_peerlist, PSF_OBFUSCATION);
	}

	if(!IsMature() || !_DHT.GetCore()->IsNetworkTimeStablized())
	{
		if((msg.fields_parsed&MSGFIELD_PEERS) && msg.peers_count)
		{
			NET_DEBUG_LOG("msg.peers_count = "<<msg.peers_count);
			_SendContactMessageToPeers(msg.peers, msg.peers_count, in_peerlist);
		}
		if((msg.fields_parsed&MSGFIELD_ALTVALS) && msg.alt_peers_count)
		{
			NET_DEBUG_LOG("msg.alt_peers_count = "<<msg.alt_peers_count);
			_SendContactMessageToPeers(msg.alt_peers, msg.alt_peers_count, in_peerlist);
		}
	}

	if(_IsActiveDiscovering() || _IsActiveAnnouncing())
	{
		if((msg.fields_parsed&MSGFIELD_NODES) && msg.nodes_size)
		{
			NET_DEBUG_LOG("msg.nodes_size = "<<msg.nodes_size);
			for(UINT i=0;i<msg.nodes_size;i++)
			{
				const DhtMessageParse::dht_compact_node& n = msg.nodes[i];
				if(!_IsNodesFull() && IsQueryAllowed(n.NetAddress))
				{
					_SendContactMessage(NetworkAddress(n.NetAddress), false, in_peerlist, PSF_DROPABLE);
				}
				else
				{	//NET_DEBUG_LOG("skip: "<<tos(n.NetAddress));
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
					_SendContactMessage(NetworkAddress(n.NetAddress), false, in_peerlist, PSF_DROPABLE);
				}
				else
				{	//NET_DEBUG_LOG("skip: "<<tos(n.NetAddress));
				}
			}
		}

		if(_RecentQueriedHosts.size() + _RecentQueriedHostsV6.size() > _RecentQueriedHostsLimit)
			_StopAllActiveWorks();
	}

	if((msg.fields_parsed&MSGFIELD_TOKEN) && msg.token_length < DHT_SWARM_TOKEN_LENGTH_MAX)
	{
		NET_DEBUG_LOG("msg.token_length = "<<msg.token_length);

		PacketBuf<> buf;
		WORD port = 0;
		if(rc.recvctx->RecvFrom.IsIPv4() && _DHT.IsPublicAddressAvailable())
			port = _DHT.GetPublicAddress().Port();
		else if(rc.recvctx->RecvFrom.IsIPv6() && _DHT.IsPublicAddressAvailableV6())
			port = _DHT.GetPublicAddressV6().Port();

		buf.Commit(_DHT.ComposeQueryAnnouncePeer(buf.Claim(), buf.SIZE, GetTarget(), port, _DHT.GetNodeDesc(), msg.token, msg.token_length, RQTAG_TXTYPE_JOINSWARM, GetTX()));

		_DHT.SendPacket(buf, rc.recvctx->RecvFrom, PSF_DROPABLE|(rc.recvctx->SendingFlag&PSF_OBFUSCATION));
		_DHT.state.AnnouncePeerSent++;
		NET_DEBUG_LOG("[NET] Annonced to "<<tos(rc.recvctx->RecvFrom));
	}
}


void DhtTxJoinSwarm::InitiatePeerAnnoucement()
{
	_bActiveAnnouncementEndTime = os::Timestamp::Get() - DHT_SWARM_ANNOUNCE_REFRESH_INTERVAL + 10*1000LL;
}

namespace _details
{

void RemoveDuplicatedInsecurePeers(DhtTxJoinSwarm& swarm, rt::BufferEx<DhtTxJoinSwarm::Node>& swarm_peers, UINT open, UINT q, NETADDR_TYPE net_type, bool is_forward, const DhtAddress& dht_addr)
{
	for(; q<swarm_peers.GetSize(); q++)
	{
		if(!swarm_peers[q].IpRestrictVerified() && 
			swarm_peers[q].NetAddress.Type() == net_type &&
			swarm_peers[q].IsForward() == is_forward &&
			swarm_peers[q].DhtAddress == dht_addr
		)
		{	swarm.RejectPeer(swarm_peers[q].NetAddress);
			continue; // remove
		}

		swarm_peers[open++] = swarm_peers[q];
	}
	swarm_peers.ShrinkSize(open);
}
} // namespace _details

DhtTxJoinSwarm::SwarmPeerContact DhtTxJoinSwarm::_OnSwarmPeerContacted(const DhtMessageParse& msg, const PacketRecvContext& ctx, UINT tick, float latency, bool auto_add, bool query)
{
	if(msg.r_id == _NodeId)return SPC_REJECT;

	bool is_sec = ctx.SendingFlag&PSF_IP_RESTRICTED_VERIFIED;
	bool half_filled = _SwarmPeersBackward.GetSize() >= _ExpectedNum/2;
	bool forward = DhtAddress::CyclicLessThan(_NodeId, msg.r_id);

	auto& swarm_peers = forward?_SwarmPeersForward:_SwarmPeersBackward;
	auto& dirty = forward?_SwarmPeersForwardDirty:_SwarmPeersBackwardDirty;

	SwarmPeerContact ret = SPC_UPDATED;

	int s;
	for(UINT i=0; i<swarm_peers.GetSize(); i++)
	{
		if(	forward == swarm_peers[i].IsForward() && 
			swarm_peers[i].DhtAddress == msg.r_id
		)
		{
			if(swarm_peers[i].NetAddress == ctx.RecvFrom ||
			   swarm_peers[i].AlternativeIP == ctx.RecvFrom)
			{	// existing peer
				if(msg.leaving_by_ping)
				{
					swarm_peers.erase(i);
					return SPC_LEAVE;
				}
				else
				{
					swarm_peers[i].last_recv = tick;
					if(query)swarm_peers[i].LastQueryRecv = tick;

					swarm_peers[i].UpdateLatency(latency);
			
					if(is_sec)
					{
						if(!swarm_peers[i].IpRestrictVerified())
						{
							dirty = true;
							swarm_peers[i].Flag |= NODE_IPRESTRICTVERIFIED;

							_RemoveDuplicatedInsecurePeers(swarm_peers, i+1, i+1, ctx.RecvFrom.Type(), forward, msg.r_id);
						}
					}

					_UpdateNodeAuxInfo(swarm_peers[i], msg, ctx.RecvFrom);

					s = i;
					goto SORT_PEERS;
				}
			}
			else if(!swarm_peers[i].IpRestrictVerified() && is_sec)
			{	// replace the insecure one with secure one, and remove all insecure ones with the same dht address
				auto_add = true;
				_RejectPeer(swarm_peers[i].NetAddress);

				_details::RemoveDuplicatedInsecurePeers(*this, swarm_peers, i, i+1, ctx.RecvFrom.Type(), forward, msg.r_id);
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
		n.DhtAddress = msg.r_id;
		n.discover_time = tick;
		n.SecureL1Distance = _SecureL1Distance(msg.r_id);
		n.last_recv = tick;
		n.last_sent = tick;
		n.LastQueryRecv = query?tick:0;
		n.latency_average = latency>-0.00001?latency:(rt::max(_AverageLatencyForward, _AverageLatencyBackward));
		n.NetAddress = ctx.RecvFrom;
		n.Flag = NODE_FLAG_ZERO;
		if(ctx.SendingFlag&PSF_IP_RESTRICTED_VERIFIED)n.Flag |= NODE_IPRESTRICTVERIFIED;
		if(forward)n.Flag |= NODE_FORWARD;

		rt::Zero(n.PeerDesc);
		rt::Zero(n.AlternativeIP);
		rt::Zero(n.ExternalIP);

		//n.BouncerCount = 0;
		//rt::Zero(n.Bouncers);

		_UpdateNodeAuxInfo(n, msg, ctx.RecvFrom);

#if defined(OXD_NET_DEBUG_REPORT)
		NET_DEBUG_LOG("add peers: "<<tos(ctx.RecvFrom.IPv4())<<" Host="<<_RecentQueriedHosts.size());
#endif

		dirty = true;

		if(!forward && half_filled != (swarm_peers.GetSize() >= _ExpectedNum/2))
			CoreEventWith(MODULE_NETWORK, NETWORK_SWARM_CHANGED, tos(GetTarget()));

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

//void DhtTxJoinSwarm::OnAnnouncePeer(const DhtMessageParse& msg, const PacketRecvContext& ctx)
//{
//	ASSERT(IsLockedByCurrentThread());
//	ASSERT(sizeof(NetworkNodeDesc) == 12);
//
//	if(IsMature())return;
//
//	if(	msg.fields_parsed&MSGFIELD_TOKEN &&
//		msg.token_length == sizeof(ULONGLONG) &&
//		*((ULONGLONG*)msg.token) == _AnnounceToken
//	)
//	{
//		NetworkAddress peer_ip = ctx.RecvFrom;
//		if(msg.fields_parsed&MSGFIELD_ANNOUNCE_PORT)
//			peer_ip.SetPort(msg.announced_port);
//
//		PacketBuf<> send_buf(	rt::SS("d1:rd2:id") + 
//								DHT_ADDRESS_SIZE + ':' + rt::String_Ref(_NodeId, DHT_ADDRESS_SIZE) +
//								rt::SS("e1:t") + 
//								msg.query_transId_length + ':' + rt::String_Ref(msg.query_transId, msg.query_transId_length) + 
//								rt::SS("2:nd12:") + rt::String_Ref((LPCSTR)&_DHT.GetNodeDesc(), 12) + 
//								rt::SS("1:y1:re")
//		);
//
//		_DHT.SendPacket(send_buf, ctx.RecvFrom, ctx.SendingFlag&PSF_OBFUSCATION_MASK);
//		_OnSwarmPeerContacted(msg, ctx, _DHT.GetTick(), -1, true, true);
//	}
//}

void DhtTxJoinSwarm::OnPing(const DhtMessageParse& msg, const PacketRecvContext& ctx)
{
	//_LOG("Ping from "<<tos(ctx.RecvFrom));

	ASSERT(!IsLockedByCurrentThread());
	if(_IsRejectedByPrivateSwarm(msg, ctx))return;

	SwarmPeerContact spc = SPC_REJECT;

	if(DHT_SWARM_QUERY_TRANSID_LENGTH != msg.query_transId_length || 
	   RQTAG_TXTYPE_CONNSWARM != (msg.query_transId[0] & RQTAG_MASK_TXTYPE)
	)
	{	EnterCSBlock(*this);
		spc = _OnSwarmPeerContacted(msg, ctx, _DHT.GetTick(), -1, true, true);
	}

	if(spc == SPC_LEAVE)return;

	PacketBuf<> buf;
	buf << 
	(	rt::SS("d") +
			rt::SS("2:ip") + ctx.RecvFrom.AddressLength() + ':' + rt::DS(ctx.RecvFrom.Address(), ctx.RecvFrom.AddressLength()) +
			rt::SS("1:r") + rt::SS("d") +
				rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
			rt::SS("e") +
			rt::SS("1:t") +
				msg.query_transId_length + ':' + rt::String_Ref(msg.query_transId, msg.query_transId_length) +
			rt::SS("1:v") + rt::SS("4:") + rt::String_Ref((LPCSTR)&DHT_VERSION_DEFAULT,4) + 
			rt::SS("3:app") + rt::SS("4:") + rt::String_Ref((LPCSTR)&_AppTag, 4) +
			rt::SS("2:nd") + rt::SS("12:") + rt::String_Ref((LPCSTR)&_DHT.GetCore()->GetNodeDesc(), 12)
	);

	if(spc != SPC_REJECT)
		_AppendCloakedIp(ctx.RecvFrom,  buf);

	if(_IsPrivateSwarm)
		_AppendPrivateSwarmPacketNum(buf, ctx.RecvFrom.Type());

	_AppendAltIp(ctx.RecvFrom, buf);

	buf << 
	(		rt::SS("1:y") + rt::SS("1:r") +
		rt::SS("e")
	);

	_DHT.SendPacket(buf, ctx.RecvFrom, PSF_DROPABLE|ctx.SendingFlag);
}

void DhtTxJoinSwarm::OnGetPeers(const DhtMessageParse& msg, const PacketRecvContext& ctx)
{
	//_LOG("GetPeer from "<<tos(ctx.RecvFrom));

	ASSERT(!IsLockedByCurrentThread());
	ASSERT(sizeof(NetworkNodeDesc) == 12);

	ASSERT(msg.info_hash);
	if(*msg.info_hash != GetTarget())
	{
		_LOG_WARNING("[BC]: Swarm Address mismatch");
		return;
	}

	if(_IsRejectedByPrivateSwarm(msg, ctx))return;

	SwarmPeerContact spc = SPC_REJECT;

	{	EnterCSBlock(*this);
		spc = _OnSwarmPeerContacted(msg, ctx, _DHT.GetTick(), -1, msg.swarm_member, true);
	}

	PacketBuf<> send_buf;
	send_buf << (	rt::SS("d1:rd2:id") + 
					DHT_ADDRESS_SIZE + ':' + rt::DS(&_NodeId, DHT_ADDRESS_SIZE)
				);

	auto& peer_list = GetPeers();

	if(peer_list.TotalCount() < _ExpectedNum)
	{	// provide nodes field
		DhtSpace::_CollectedNode nodes[DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE];

		if(ctx.RecvFrom.Type() == NADDRT_IPV4)
		{
			UINT cco = _DHT.GetClosestNodes(GetTarget(), nodes, sizeofArray(nodes));
			if(cco)
			{
				send_buf << (rt::SS("5:nodes") + (UINT)(cco *sizeof(DhtMessageParse::dht_compact_node)) + ':');
				auto* final_nodes = (DhtMessageParse::dht_compact_node*)send_buf.Claim(cco*sizeof(DhtMessageParse::dht_compact_node));
				for(UINT i=0; i<cco; i++)
				{
					final_nodes[i].DhtAddress = nodes[i].node.DhtAddress;
					final_nodes[i].NetAddress = nodes[i].node.NetAddress.IPv4();
				}

				send_buf.Commit(cco * sizeof(DhtMessageParse::dht_compact_node));
			}
		}
		else if(ctx.RecvFrom.Type() == NADDRT_IPV6)
		{
			UINT cco = _DHT.GetClosestNodesIPv6(GetTarget(), nodes, sizeofArray(nodes));
			if(cco)
			{
				send_buf << (rt::SS("6:nodes6") + (UINT)(cco *sizeof(DhtMessageParse::dht_compact_node_v6)) + ':');
				auto* final_nodes = (DhtMessageParse::dht_compact_node_v6*)send_buf.Claim(cco*sizeof(DhtMessageParse::dht_compact_node_v6));
				for(UINT i=0; i<cco; i++)
				{
					final_nodes[i].DhtAddress = nodes[i].node.DhtAddress;
					final_nodes[i].NetAddress = nodes[i].node.NetAddress.IPv6();
				}

				send_buf.Commit(cco * sizeof(DhtMessageParse::dht_compact_node_v6));
			}
		}
	}

	bool no_announce = false;
	if(peer_list.TotalCount())
	{
		UINT co = 0;
		auto collect = [&co, &send_buf, &no_announce, &ctx, &peer_list](DWORD inet_type){
			for(UINT i = 0; i < peer_list.TotalCount(); i++)
			{
				if(peer_list.Peers[i].Type() == inet_type)
				{
					if(inet_type == NADDRT_IPV6)
						send_buf << (rt::SS("18:") + rt::DS(peer_list.Peers[i].IPv6()));
					else
					{	ASSERT(inet_type == NADDRT_IPV4);
						send_buf << (rt::SS("6:") + rt::DS(peer_list.Peers[i].IPv4()));
					}

					if(ctx.RecvFrom == peer_list.Peers[i])
						no_announce = true;

					co--;
					if(co <= 0)break;
				}
			}
		};

		send_buf << rt::SS("6:valuesl");
		{
			if(ctx.RecvFrom.Type() == NADDRT_IPV6)
			{
				co = DHT_SWARM_REPLY_PEERLIST_MAX_V6;
				collect(NADDRT_IPV6);
			}
			else
			{
				ASSERT(ctx.RecvFrom.Type() == NADDRT_IPV4);
				co = DHT_SWARM_REPLY_PEERLIST_MAX;
				collect(NADDRT_IPV4);
			}
		}
		send_buf << rt::SS("e");

		send_buf << rt::SS("7:altvalsl");
		{
			if(ctx.RecvFrom.Type() == NADDRT_IPV6)
			{
				co = DHT_SWARM_REPLY_PEERLIST_MAX;
				collect(NADDRT_IPV4);
			}
			else
			{
				ASSERT(ctx.RecvFrom.Type() == NADDRT_IPV4);
				co = DHT_SWARM_REPLY_PEERLIST_MAX_V6;
				collect(NADDRT_IPV6);
			}
		}
		send_buf << rt::SS("e");
	}

	//if(!no_announce)
	// send_buf << (rt::SS("5:token") + (UINT)sizeof(ULONGLONG) + ':' + rt::String_Ref((LPCSTR)&_AnnounceToken, sizeof(ULONGLONG)));

	send_buf << rt::SS("4:swmb1:1");
	send_buf << (rt::SS("e1:t") +
				msg.query_transId_length + ':' + rt::String_Ref(msg.query_transId, msg.query_transId_length) +
				rt::SS("2:nd12:") + rt::String_Ref((LPCSTR)&_DHT.GetNodeDesc(), 12));

	if(spc != SPC_REJECT)
		_AppendCloakedIp(ctx.RecvFrom, send_buf);

	//if(ctx.RecvFrom.IsIPv4() && _DHT.IsPublicAddressAvailableV6())
	//{
	//	send_buf << (rt::SS("5:altip") + rt::SS("18:") + rt::DS(&_DHT.GetPublicAddressV6(), 18));
	//}
	//else if(ctx.RecvFrom.IsIPv6() && _DHT.IsPublicAddressAvailable())
	//{
	//	send_buf << (rt::SS("5:altip") + rt::SS("6:") + rt::DS(&_DHT.GetPublicAddress(), 6));
	//}

	if(_IsPrivateSwarm)
		_AppendPrivateSwarmPacketNum(send_buf, ctx.RecvFrom.Type());

	_AppendAltIp(ctx.RecvFrom, send_buf);

	send_buf << (rt::SS("2:ip") + ctx.RecvFrom.AddressLength() + ':' + rt::DS(ctx.RecvFrom.Address(), ctx.RecvFrom.AddressLength()));
	send_buf << rt::SS("1:y1:re");
	_DHT.SendPacket(send_buf, ctx.RecvFrom, PSF_DROPABLE|(ctx.SendingFlag&PSF_OBFUSCATION));
}

void DhtTxJoinSwarm::_ActiveAnnouncePeer()
{
	_bActiveAnnouncementStartTime = os::Timestamp::Get();

	DhtSpace::_CollectedNode nodes[DHT_SWARM_ANNOUNCE_FANOUT_SIZE];
	UINT ncount = _DHT.GetClosestNodes(GetTarget(), nodes, DHT_SWARM_ANNOUNCE_FANOUT_SIZE);

	DhtSpace::_CollectedNode nodesv6[DHT_SWARM_ANNOUNCE_FANOUT_SIZE];
	UINT ncountv6 = _DHT.GetClosestNodesIPv6(GetTarget(), nodesv6, DHT_SWARM_ANNOUNCE_FANOUT_SIZE);

	PacketBuf<> bufv4, bufv6;
	NetworkAddress altipv4, altipv6;
	if(_DHT.IsPublicAddressAvailableV6())
	{
		auto& ip = _DHT.GetPublicAddressV6();
		if(!ip.IsTrivial())
			altipv6.IPv6() = ip;
	}

	if(_DHT.IsPublicAddressAvailable())
		altipv4.IPv4() = _DHT.GetPublicAddress();

	bufv4.Commit(_DHT.ComposeQueryGetPeer(bufv4.Claim(), bufv4.SIZE, GetTarget(), _DHT.GetNodeDesc(), altipv6, TX_TYPE, GetTX(), true));
	ASSERT(bufv4.GetLength());

	bufv6.Commit(_DHT.ComposeQueryGetPeer(bufv6.Claim(), bufv6.SIZE, GetTarget(), _DHT.GetNodeDesc(), altipv4, TX_TYPE, GetTX(), true));
	ASSERT(bufv6.GetLength());

	DhtTxRecentHosts::SetCapacityHint(_ExpectedNum*DHT_SWARM_ANNOUNCE_HOSTS_MAX*3/2);
	DhtTxRecentHosts::SetHardLimit(_ExpectedNum*DHT_SWARM_ANNOUNCE_HOSTS_MAX);
	DhtTxRecentHosts::SetRecentPeriod(3600000);

	for(UINT i=0; i<ncount; i++)
	{
		_DHT.SendPacket(bufv4, nodes[i].node.NetAddress, PSF_DROPABLE);  // no obfuscation
		AddQueried(nodes[i].node.NetAddress);
		_DHT.state.GetPeerSent++;
	}

	for(UINT i=0; i<ncountv6; i++)
	{
		_DHT.SendPacket(bufv6, nodesv6[i].node.NetAddress, PSF_DROPABLE);  // no obfuscation
		AddQueried(nodesv6[i].node.NetAddress);
		_DHT.state.GetPeerSent++;
	}

#ifdef OXD_NET_DEBUG_REPORT
	_LOG_WARNING("Active Announcement at "<<rt::tos::Timestamp<>(_bActiveAnnouncementStartTime)<<" fanout="<<ncount + ncountv6);
#endif
}


void DhtTxJoinSwarm::_UpdateOutputPeers(bool enforce)
{
	ASSERT(IsLockedByCurrentThread());

	if(!_SwarmPeersBackwardDirty && !_SwarmPeersForwardDirty && !enforce)
		return;

	UINT tick = _DHT.GetTick();

	_OutputPeers_Back->BackwardCount = 0;
	_OutputPeers_Back->ForwardCount = 0;

	UINT established_backward;
	thread_local rt::BufferEx<rt::PodRef<Node>> forward_sorted;
	ASSERT(forward_sorted.GetSize() == 0);

	if(_SwarmPeersBackwardDirty || enforce)
	{
		thread_local rt::BufferEx<rt::PodRef<Node>> backward_sorted;
		ASSERT(backward_sorted.GetSize() == 0);

		// resorting establishment is higher proirity
		for(auto& p : _SwarmPeersBackward)
		{
			if(p.IsAlive(tick))
			{
				if(p.IsBackwardEstablished(tick) && p.IpRestrictVerified())
				{
					backward_sorted.push_back(p);
				}
				else
				{
					forward_sorted.push_back(p);
				}
			}
			else p.Flag |= NODE_DISCARD;
		}

		established_backward = (UINT)backward_sorted.GetSize();
		backward_sorted.push_back(forward_sorted.Begin(), forward_sorted.GetSize());
		forward_sorted.ShrinkSize(0);

		// mark aged and unused backwards as removal
		bool removed = false;
		if(backward_sorted.GetSize() > _ExpectedNum + 2)
		{
			for(UINT i = _ExpectedNum + 2; i<backward_sorted.GetSize(); i++)
			{
				if(backward_sorted[i]->Age(tick) > DHT_SWARM_STABLE_AGE)
				{
					backward_sorted[i]->Flag |= NODE_DISCARD;
					_RejectPeer(backward_sorted[i]->NetAddress);
					removed = true;
				}
			}
		}
		backward_sorted.ShrinkSize(_ExpectedNum);

		_OutputPeers_Back->BackwardCount = (UINT)backward_sorted.GetSize();
		for(UINT i=0; i<backward_sorted.GetSize(); i++)
			_OutputPeers_Back->Peers[i] = backward_sorted[i]->NetAddress;
		backward_sorted.ShrinkSize(0);

		if(removed)
		{	// remove peers that marked
			UINT i=0;
			for(; i<_SwarmPeersBackward.GetSize(); i++)
				if(_SwarmPeersBackward[i].Flag&NODE_DISCARD)
					break;

			ASSERT(i<_SwarmPeersBackward.GetSize());
			UINT new_size = i;
				
			for(; i<_SwarmPeersBackward.GetSize(); i++)
			{
				if(_SwarmPeersBackward[i].Flag&NODE_DISCARD)
					continue;

				_SwarmPeersBackward[new_size++] = _SwarmPeersBackward[i];
			}
			_SwarmPeersBackward.ShrinkSize(new_size);
		}
	}
	else
	{	// reuse previous list
		_OutputPeers_Back->BackwardCount = _OutputPeers_Front->BackwardCount;
		memcpy(_OutputPeers_Back->BackwardPeers(), _OutputPeers_Front->BackwardPeers(), _OutputPeers_Back->BackwardCount*sizeof(NetworkAddress));
		established_backward = _EstablishedBackward;
	}

	if(_SwarmPeersForwardDirty || enforce)
	{
		auto* fwd = _OutputPeers_Back->ForwardPeers();
		if(_SwarmPeersForward.GetSize() <= 2)
		{
			for(UINT i=0; i<_SwarmPeersForward.GetSize(); i++)
				fwd[i] = _SwarmPeersForward[i].NetAddress;

			_OutputPeers_Back->ForwardCount = (UINT)_SwarmPeersForward.GetSize();
		}
		else
		{	// keep first 2 with best latency
			_OutputPeers_Back->ForwardCount = 2;
			fwd[0] = _SwarmPeersForward[0].NetAddress;
			fwd[1] = _SwarmPeersForward[1].NetAddress;

			ASSERT(forward_sorted.GetSize() == 0);
			struct compr_L1distance
			{	bool operator ()(const rt::PodRef<Node>& a, const rt::PodRef<Node>& b) const
				{ return a->SecureL1Distance < b->SecureL1Distance; }
			};

			compr_L1distance c;
			for(UINT i=2; i<_SwarmPeersForward.GetSize(); i++)
			{
				if(_SwarmPeersForward[i].IsAlive(tick) && _SwarmPeersForward[i].IpRestrictVerified())
					forward_sorted.PushSorted(_SwarmPeersForward[i], c);
				else
					_SwarmPeersForward[i].Flag |= NODE_DISCARD;
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
				for(; i<_SwarmPeersForward.GetSize(); i++)
					if(_SwarmPeersForward[i].Flag&NODE_DISCARD)
						break;

				ASSERT(i<_SwarmPeersForward.GetSize());
				UINT new_size = i;
				
				for(; i<_SwarmPeersForward.GetSize(); i++)
				{
					if(_SwarmPeersForward[i].Flag&NODE_DISCARD)
						continue;

					_SwarmPeersForward[new_size++] = _SwarmPeersForward[i];
				}

				_SwarmPeersForward.ShrinkSize(new_size);
			}
		}
	}
	else
	{	// reuse previous list
		_OutputPeers_Back->ForwardCount = _OutputPeers_Front->ForwardCount;
		memcpy(_OutputPeers_Back->ForwardPeers(), _OutputPeers_Front->ForwardPeers(), _OutputPeers_Back->ForwardCount*sizeof(NetworkAddress));
	}

	_SwarmPeersBackwardDirty = false;
	_SwarmPeersForwardDirty = false;

	rt::Swap(_OutputPeers_Front, _OutputPeers_Back);
	_EstablishedBackward = established_backward;
	_DiscoveredForward = (UINT)_SwarmPeersForward.GetSize();

	_CheckHeap;
	ASSERT(_OutputPeers_Front->TotalCount() <= _ExpectedNum*2);
	ASSERT(_OutputPeers_Back->TotalCount() <= _ExpectedNum*2);
}

bool DhtTxJoinSwarm::IsMature() const 
{
	return _EstablishedBackward >= _ExpectedNum/2 && _DiscoveredForward > _ExpectedNum/2;
}

void DhtTxJoinSwarm::Awaken()
{
    EnterCSBlock(*this);
    _PingAllPeers(true);
}

void DhtTxJoinSwarm::CopyPeersAsBouncers(rt::BufferEx<NetworkAddress>& bouncers, rt::BufferEx<NetworkAddress>& bouncers_altip, rt::BufferEx<NetworkAddress>& destination)
{
	EnterCSBlock(*this);

	auto tick = _DHT.GetTick();
	for(auto& it : _SwarmPeersBackward)
	{
		if(it.ExternalIP.IsEmpty())continue;

		if(it.IsBackwardEstablished(tick))		// Only establised backward serves as bouncer
		{
			bouncers.push_back(it.NetAddress);
			bouncers_altip.push_back(it.AlternativeIP);
			destination.push_back(it.ExternalIP);
		}
	}
}

void DhtTxJoinSwarm::Leave()
{
	PacketBuf<> buf;
  
	buf <<
	(	rt::SS("d1:ad") +
			rt::SS("2:id") +	 DHT_ADDRESS_SIZE + ':' + rt::DS(&_NodeId, DHT_ADDRESS_SIZE) +
			rt::SS("6:target") + DHT_ADDRESS_SIZE + ':' + rt::DS(&GetTarget(), DHT_ADDRESS_SIZE) +
			rt::SS("e1:q4:ping1:t9:") + ((char)(_TX_TYPE | RQTAG_VERB_PING)) +
			rt::DS(_DHT._TransToken, 2) +  /* WORD Transaction id for better security (reply message should be received from nodes we contacted*/
			rt::DS(&_TX, 2) +
			rt::DS(&_DHT._Tick, 4) + /* UINT send _Tick, for estimating round trip latency */
			rt::SS("5:leave1:1") +   // leaving flag
			rt::SS("1:v4:") + rt::DS(&_DHT._DhtVer, 4) +
			rt::SS("3:app4:") + rt::DS(&_AppTag, 4) +
			rt::SS("2:nd") + rt::SS("12:") + rt::DS(&_DHT.GetCore()->GetNodeDesc(), 12)
	);

	buf << 	rt::SS("1:y1:qe");

	ASSERT(buf.GetLength());

	EnterCSBlock(*this);
	for(auto& it : _SwarmPeersBackward)
	{
		_DHT.SendPacket(buf, it.NetAddress, PSF_NORMAL);
	}
	
	for(auto& it : _SwarmPeersForward)
	{
		_DHT.SendPacket(buf, it.NetAddress, PSF_NORMAL);
	}
}

void DhtTxJoinSwarm::_PingAllPeers(bool force)
{
    bool no_discover = (IsMature() || _IsNodesFull()) && _DHT.GetCore()->IsNetworkTimeStablized();
	
    if(force || _PingPeersForwardTimer((int)_DHT.GetTick()))
        _AverageLatencyForward = _PingScan(no_discover, force, _SwarmPeersForward);

    if(force || _PingPeersBackwardTimer((int)_DHT.GetTick()))
        _AverageLatencyBackward = _PingScan(no_discover, force, _SwarmPeersBackward);
}

void DhtTxJoinSwarm::Iterate()
{
	ASSERT(IsLockedByCurrentThread());

	if(!_IsActiveAnnouncing() && !_IsActiveDiscovering())
		DhtTxRecentHosts::Iterate();

	if(_SwarmPeersBackwardDirty || _SwarmPeersForwardDirty)
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

	if(_IsActiveAnnouncing())
	{
		if(os::Timestamp::Get() > DHT_SWARM_ANNOUNCE_REFRESH_PERIOD + _bActiveAnnouncementStartTime)
		{	
			_LOGC("[NET]: Swarm "<<tos(_Target)<<" peer announcement finished");
			_StopAllActiveWorks();
		}
	}
	else
	{
		if(!_DHT.GetCore()->IsDataServiceSuspended() && !_IsActiveDiscovering() && os::Timestamp::Get() > DHT_SWARM_ANNOUNCE_REFRESH_INTERVAL + _bActiveAnnouncementEndTime)
		{
			_ActiveAnnouncePeer();
		}
	}

	if(_IsActiveDiscovering())
	{
		if(!_ActiveDiscoveredByStockBootstrapList && 
			_SwarmPeersForward.GetSize() == 0 && 
			_SwarmPeersBackward.GetSize() == 0 && 
			_ActiveDiscoveringStartTime + DHT_SWARM_USE_STOCK_BOOTSTRAP_AFTER < os::Timestamp::Get()
		)
		{	_ActiveDiscoveredByStockBootstrapList = true;
			_SendContactMessageFromBootstrapFile();
		}

		if(	(_SwarmPeersForward.GetSize() > _ExpectedNum/2 && _SwarmPeersBackward.GetSize() > _ExpectedNum) || 
			DhtTxRecentHosts::IsFull() || // hosts exhausted
			_ActiveDiscoveringStartTime + DHT_SWARM_BOOTSTRAP_TIMEOUT < os::Timestamp::Get() // timeout
		)
		{	//_LOGC("[NET]: Swarm "<<tos(_Target)<<" peer discovery finished");
			_StopAllActiveWorks();
		}
	}

	if(_SwarmPeersForward.GetSize() || _SwarmPeersBackward.GetSize())
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

void DhtTxJoinSwarm::_StopAllActiveWorks()
{
	ASSERT(IsLockedByCurrentThread());

	_HostsClearTime = os::Timestamp::Get() + DHT_SWARM_HOSTS_FORGET_INTERVAL;
	_ActiveDiscoveringStartTime = 0;
	_bActiveAnnouncementStartTime = 0;
	_bActiveAnnouncementEndTime = os::Timestamp::Get() + (DHT_SWARM_ANNOUNCE_REFRESH_INTERVAL*rand()/RAND_MAX) - DHT_SWARM_ANNOUNCE_REFRESH_INTERVAL/2;
}

void DhtTxJoinSwarm::_UpdateBootstrapList()
{
	ASSERT(IsLockedByCurrentThread());

	ext::fast_map<NetworkAddress, NetworkAddress> list;
	if(_SwarmPeersForward.GetSize() == 0 && _SwarmPeersBackward.GetSize() == 0)return;

	for(auto& p : _SwarmPeersForward)list.insert(std::make_pair(p.NetAddress, p.AlternativeIP));
	for(auto& p : _SwarmPeersBackward)list.insert(std::make_pair(p.NetAddress, p.AlternativeIP));

    // unlock don't let file I/O block the swarm processing
	Unlock();

	auto& addr = this->GetTarget();
	rt::String fn = _DHT.GetCore()->GetCachePath() + '/' + rt::tos::Base32LowercaseOnStack<>(addr) + DHT_SWARM_BOOTSTRAP_EXTNAME;

	_details::LoadSwarmNetworkAddressTable(fn, list, DHT_BOOTSTRAP_NODES_MAX);

	if(!_details::SaveSwarmNetworkAddressTable(fn, list))
		_LOG_WARNING("Failed to save swarm bootstrap list: "<<fn);

	Lock();
}

void DhtTxJoinSwarm::GetStateReport(rt::String& out, UINT tick)
{
	EnterCSBlock(*this);

	out +=	rt::SS("#") + rt::tos::Number(_TX).LeftAlign(3) + "Swarm: " + tos(GetTarget()) + 
			rt::SS("\n    Node:  ") + tos(_NodeId) + 
			"\nFWD:" + _SwarmPeersForward.GetSize() + '/' + _ExpectedNum + 
			" BCK:" + _SwarmPeersBackward.GetSize() + '/' + _ExpectedNum + 
			" LNTC:" + (int)(_AverageLatencyForward*NET_TICK_UNIT_FLOAT + 0.5f) + '/' + (int)(_AverageLatencyBackward*NET_TICK_UNIT_FLOAT + 0.5f) + 
			" HOSTS:" + (int)_RecentQueriedHosts.size() + '/' + (int)_RecentQueriedHostsV6.size();

	if(!IsMature())out +=  " Immature";
	if(_IsPrivateSwarm)out +=  " Private";
	if(_IsActiveDiscovering())out += " Discovering";
	if(_IsActiveAnnouncing())out += " Announcing";
	out += '\n';

	_PrintPeers(false, _SwarmPeersBackward, out);
	_PrintPeers(true, _SwarmPeersForward, out);
}

void DhtTxJoinSwarm::Jsonify(rt::Json& json) const
{
	DhtTxSwarm::Jsonify(json);
	json.ScopeMergingObject()->Object((
		J(peers) = JA(_SwarmPeersForward.GetSize(), _SwarmPeersBackward.GetSize())
	));
}

void DhtTxJoinSwarm::_SendContactMessageToPeers(const NetworkAddress* peers, uint32_t count, bool in_peerlist)
{
	for(uint32_t i = 0; i < count; i++)
	{
		auto& p = peers[i];
		if(	(_SwarmPeersForward.GetSize() < _ExpectedNum || _SwarmPeersBackward.GetSize() < _ExpectedNum*2 || !_DHT.GetCore()->IsNetworkTimeStablized())
				&& IsQueryAllowed(p)
		)
		{	_SendContactMessage(p, _IsNodesFull(), in_peerlist, PSF_DROPABLE|PSF_OBFUSCATION);
		}
		//else
		//{	NET_DEBUG_LOG("skip: "<<tos(p));
		//}
	}
}

} // namespace upw
