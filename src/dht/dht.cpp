#include "dht.h"
#include "../../externs/miniposix/core/ext/ipp/ipp_core.h"
#include "../netsvc_core.h"
#include "dht_space.h"
#include "dht_tx_joinswarm.h"
#include "dht_tx_connswarm.h"
#include "dht_bootstrap.inc"

#include <set>


namespace upw
{

void MainlineDHT::_UpdatePrecomputedMessagesTransId()
{
	ASSERT(DHT_ADDRESS_SIZE < 100);

	ULONGLONG TxTick = (((ULONGLONG)_TransToken[0]))|(((ULONGLONG)_Tick)<<32);

	*((ULONGLONG*)(_PrecomputedMessages._PingMessage.GetData() + 9 + 2 + 1 + DHT_ADDRESS_SIZE + 16))
		= TxTick;

	*((ULONGLONG*)(_PrecomputedMessages._FindMyselfMessage.GetData() + 9 + 2 + 1 + DHT_ADDRESS_SIZE + 8 + 2 + 1 + DHT_ADDRESS_SIZE + 21))
		= TxTick;
}

void MainlineDHT::_PrecomputeMessages()
{
	_PrecomputedMessages._PingMessage.Reset();
	_PrecomputedMessages._PingMessage.Commit(
		ComposeQueryPing(	_PrecomputedMessages._PingMessage.Claim(), 
							_PrecomputedMessages._PingMessage.SIZE,
							RQTAG_TXTYPE_ROUTING, 0
		)
	);

	_PrecomputedMessages._FindMyselfMessage.Reset();
	_PrecomputedMessages._FindMyselfMessage.Commit(
		ComposeQueryFindNode(	_PrecomputedMessages._FindMyselfMessage.Claim(),
								_PrecomputedMessages._FindMyselfMessage.SIZE,
								GetNodeId(),
								RQTAG_TXTYPE_ROUTING, 0
		)
	);
}

MainlineDHT::MainlineDHT(NetworkServiceCore* datagram_net, const DhtAddress& node_own_address, const NetworkNodeDesc& nd)
	:_NodeDiscovered(DHT_SPACE_DISCOVER_QUEUE_MAXSIZE),
	 _NodeDiscoveredIPv6(DHT_SPACE_DISCOVER_QUEUE_MAXSIZE)
{
	rt::Zero(state);
	_pNodeDesc = &nd;
	_BootstrapBoostCountDown = DHT_BOOTSTRAP_BOOST_COUNT;
	_BootstrapBoostCountDownIPv6 = DHT_BOOTSTRAP_BOOST_COUNT;

	_NodeId = node_own_address;

	_ResponseToFindQueries = true;
	_ResponseToGetPeerQueries = true;
	_ResponseToAnounnceQueries = true;

	_pNet = datagram_net;
	_Tick = datagram_net->GetTick();

	datagram_net->SetPacketOnRecvCallBack(NET_PACKET_HEADBYTE_DHT, this, &MainlineDHT::_OnRecv);

	ResetExternalIP();

#if defined(OXD_DUMP_DHT_MESSAGE)
	VERIFY(_log_Message.Open("dht_messages.log", os::File::Normal_Write));
	_log_Message_timer.LoadCurrentTime();
#endif
}

void MainlineDHT::ResetExternalIP()
{
	{	EnterCSBlock(_PublicIPv4CS);
		_PublicIPv4.ClampWeight(DHT_NODE_EXTERNAL_IP_MATURE);
	}

	{	EnterCSBlock(_PublicIPv6CS);
		_PublicIPv6.ClampWeight(DHT_NODE_EXTERNAL_IP_MATURE);
	}
}

void MainlineDHT::ForceRefresh()
{
	_fd_SpaceUpdate.Reset();
	_fd_SpaceUpdateIPv6.Reset();

	_TransToken[0] = 0;
	_ChangeToken();
	_BootstrapBoostCountDown = DHT_BOOTSTRAP_BOOST_COUNT;
	_BootstrapBoostCountDownIPv6 = DHT_BOOTSTRAP_BOOST_COUNT;

	ResetExternalIP();
	_PrecomputeMessages();
	_Bootstrap();
	_BootstrapIPv6();
}

void MainlineDHT::Awaken()
{
    _TransToken[0] = 0;
    _ChangeToken();

  	_PrecomputeMessages();
	_Bootstrap();
	_BootstrapIPv6();
  
	_JoinSwarms.Awaken();
	_ConnSwarms.Awaken();
}

MainlineDHT::~MainlineDHT()
{
}

UINT MainlineDHT::StartFindingNode(const DhtAddress& target)
{
	_bHasImmatureTxn = true;
	DhtTxFindNode* p = _FindingNodes.Create(*this, target);
	ASSERT(p);
	EnterCSBlock(*p);
	p->KickOff();
	return p->GetTX();
}

void MainlineDHT::StopFindingNode(UINT FindingId)
{
	_FindingNodes.Destroy(FindingId); 
}

UINT MainlineDHT::StartJoinSwarm(const DhtAddress& target, UINT swarm_size, const rt::String_Ref& boot_file)	// return FindingId, nullptr for error
{
	_bHasImmatureTxn = true;
	DhtTxJoinSwarm* p = _JoinSwarms.Create(*this, target, swarm_size, nullptr, DHT_APP_TAG_DEFAULT, nullptr, boot_file);
	ASSERT(p);
	p->Bootstrap();

	return p->GetTX();
}

UINT MainlineDHT::StartJoinPrivateSwarm(const DhtAddress& target, const DhtAddress& private_secret, UINT swarm_size, const DhtAddress* alt_node_id, const rt::String_Ref& boot_file)
{
	_bHasImmatureTxn = true;
	DhtTxJoinSwarm* p = _JoinSwarms.Create(*this, target, swarm_size, alt_node_id, DHT_APP_TAG_DEFAULT, &private_secret, boot_file);
	ASSERT(p);
	p->Bootstrap();

	return p->GetTX();
}

void MainlineDHT::StopJoinSwarm(UINT SwarmId)
{
	_JoinSwarms.Destroy(SwarmId);
}

const PeerList& MainlineDHT::GetSwarmPeers(UINT swarm_id)
{
	auto* p = _JoinSwarms.Get(swarm_id);
	if(p)return p->GetPeers();
	else
	{
		static const rt::_details::Zeros<sizeof(PeerList)> _;
		return (const PeerList&)_;
	}
}

bool MainlineDHT::IsSwarmMature(UINT swarm_id) const
{
	auto* p = _JoinSwarms.Get(swarm_id);
	return p && p->IsMature();
}

void MainlineDHT::SetSwarmPeerEventCallback(UINT swarm_id, DhtSwarmEventCallback cb, LPVOID cookie)
{
	auto* p = _JoinSwarms.Get(swarm_id);
	if(p)p->SetPeerEventCallback(cb, cookie);
}

void MainlineDHT::InitiatePeerAnnoucement()
{
	_JoinSwarms.InitiatePeerAnnoucement();
}

UINT MainlineDHT::StartConnSwarm(const DhtAddress& target, UINT swarm_size, const rt::String_Ref& boot_file)	// return FindingId, nullptr for error
{
	_bHasImmatureTxn = true;
	DhtTxConnSwarm* p = _ConnSwarms.Create(*this, target, swarm_size, nullptr, DHT_APP_TAG_DEFAULT, nullptr, boot_file);
	ASSERT(p);
	p->Bootstrap();

	return p->GetTX();
}

UINT MainlineDHT::StartConnPrivateSwarm(const DhtAddress& target, const DhtAddress& private_secret, UINT swarm_size, const DhtAddress* alt_node_id, const rt::String_Ref& boot_file)
{
	_bHasImmatureTxn = true;
	DhtTxConnSwarm* p = _ConnSwarms.Create(*this, target, swarm_size, alt_node_id, DHT_APP_TAG_DEFAULT, &private_secret, boot_file);
	ASSERT(p);
	p->Bootstrap();

	return p->GetTX();
}

void MainlineDHT::StopConnSwarm(UINT SwarmId)
{
	_ConnSwarms.Destroy(SwarmId);
}

const PeerList& MainlineDHT::GetConnSwarmPeers(UINT swarm_id)
{
	auto* p = _ConnSwarms.Get(swarm_id);
	if(p)return p->GetPeers();
	else
	{
		static const rt::_details::Zeros<sizeof(PeerList)> _;
		return (const PeerList&)_;
	}
}

bool MainlineDHT::IsConnSwarmMature(UINT swarm_id) const
{
	auto* p = _ConnSwarms.Get(swarm_id);
	return p && p->IsMature();
}

void MainlineDHT::SetConnSwarmPeerEventCallback(UINT swarm_id, DhtSwarmEventCallback cb, LPVOID cookie)
{
	auto* p = _ConnSwarms.Get(swarm_id);
	if(p)p->SetPeerEventCallback(cb, cookie);
}


void MainlineDHT::OnTick(UINT tick)
{
	_Tick = tick;

	// Update Tick and Precomputed Messages
	if((_Tick%DHT_TOKEN_UPDATE_INTERVAL) == 0)
	{	// Update Transaction id
		_ChangeToken();
	}
	_UpdatePrecomputedMessagesTransId();

	{
		THREADSAFEMUTABLE_SCOPE(_DhtSpace);
		if(_DhtSpace.GetImmutable().GetNodeCount() == 0)
		{
			if(_fd_BootstrapBoost(_Tick) && _BootstrapBoostCountDown>0)
			{
				_BootstrapBoostCountDown--;
				_Bootstrap();
			}
		}
		else
		{	if(!IsMatureIPv4() && _fd_Bootstrap(_Tick))
				_Bootstrap();
		}
	}

	{
		THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
		if(_DhtSpaceIPv6.GetImmutable().GetNodeCount() == 0)
		{
			if(_fd_BootstrapBoostIPv6(_Tick) && _BootstrapBoostCountDownIPv6>0)
			{
				_BootstrapBoostCountDownIPv6--;
				_BootstrapIPv6();
			}
		}
		else
		{	if(!IsMatureIPv6() && _fd_BootstrapIPv6(_Tick))
				_BootstrapIPv6();
		}
	}


	if((tick%10) == 0)
	{
		bool dht_mature_v4 = IsMatureIPv4();
		bool dht_mature_v6 = IsMatureIPv6();
		if(_bHasImmatureTxn)
		{
			_bHasImmatureTxn =	_FindingNodes.HasImmature() ||
								_JoinSwarms.HasImmature() ||
								_ConnSwarms.HasImmature();
		}

		// Update IPv4 DHT Space
		if(!dht_mature_v4 || _bHasImmatureTxn || _fd_SpaceUpdate(_Tick))
		{	
			_fd_SpaceUpdate.SetInterval(_Iterate_UpdateDhtSpace());
		}

		// Update IPv6 DHT Space
		if(!dht_mature_v6 || _bHasImmatureTxn || _fd_SpaceUpdateIPv6(_Tick))
		{
			_fd_SpaceUpdateIPv6.SetInterval(_Iterate_UpdateDhtSpaceIPv6());
		}

		if((dht_mature_v4 || dht_mature_v6) && _fd_BootstrapUpdate(_Tick))
			UpdateBootstrapList();

		//if(!dht_mature && IsMature())
		//{
		//	for(auto p : _FindingNodes.Txns())
		//		p->KickOff(PSF_OBFUSCATION_PROBE);

		//	for(auto p : _FindingNodes.Txns())
		//		p->KickOff(PSF_OBFUSCATION_PROBE);
		//}
	}

	// Update transaction
	if((_Tick%DHT_TRANSCATION_ITERATE_INTERVAL) == 0)
	{	
		_FindingNodes.Iterate();
		_JoinSwarms.Iterate();
		_ConnSwarms.Iterate();
	}
}

UINT MainlineDHT::_Iterate_UpdateDhtSpace()
{
	{	THREADSAFEMUTABLE_SCOPE(_DhtSpace);
		const DhtSpace& space = _DhtSpace.GetImmutable();

		{	THREADSAFEMUTABLE_UPDATE(_DhtSpace, space_next);
			space_next.ReadyModify(true);
			// copy to the next space and remove dead nodes
			space_next->Rebuild(space, *this);
			space_next->DiscoverNewNodes(this, _NodeDiscovered, _Tick);

			// Finalize
			space_next->FinalizeUpdate(_Tick, _NodeId);

			if(space.IsMature(_Tick) != space_next->IsMature(_Tick))
				CoreEvent(MODULE_NETWORK, NETWORK_CONNECTIVITY_CHANGED);
		}
	}


	// send find self to dropped nodes
	//for(UINT i=0;i<discovery_queue.any_message._Used;i++)
	//	if(	discovery_queue.any_message._Queue[i].bucket >= 1 &&
	//		space_next._Buckets[discovery_queue.any_message._Queue[i].bucket-1].IsAcceptingNewNode()
	//	) // dropped node
	//	{	_SendFindSelf(discovery_queue.any_message._Queue[i].nodeinfo.NetAddress);
	//	}

	THREADSAFEMUTABLE_SCOPE(_DhtSpace);
	UINT space_update_interval = 
		_DhtSpace.GetImmutable().GetNodeCount()*(DHT_SPACE_UPDATE_INTERVAL_MAX-DHT_SPACE_UPDATE_INTERVAL_MIN)
		/ (DHT_BUCKET_SIZE*(DHT_ADDRESS_SIZE*8+1))
		+ DHT_SPACE_UPDATE_INTERVAL_MIN;

	return space_update_interval;
}

UINT MainlineDHT::_Iterate_UpdateDhtSpaceIPv6()
{
	{	THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
		const DhtSpace& space = _DhtSpaceIPv6.GetImmutable();

		{	THREADSAFEMUTABLE_UPDATE(_DhtSpaceIPv6, space_next);
			space_next.ReadyModify(true);
			// copy to the next space and remove dead nodes
			space_next->Rebuild(space, *this);
			space_next->DiscoverNewNodes(this, _NodeDiscoveredIPv6, _Tick);

			// Finalize
			space_next->FinalizeUpdate(_Tick, _NodeId);

			if(space.IsMature(_Tick) != space_next->IsMature(_Tick))
				CoreEvent(MODULE_NETWORK, NETWORK_CONNECTIVITY_CHANGED);
		}
	}

	THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
	UINT space_update_interval = 
		_DhtSpaceIPv6.GetImmutable().GetNodeCount()*(DHT_SPACE_UPDATE_INTERVAL_MAX-DHT_SPACE_UPDATE_INTERVAL_MIN)
		/ (DHT_BUCKET_SIZE*(DHT_ADDRESS_SIZE*8+1))
		+ DHT_SPACE_UPDATE_INTERVAL_MIN;

	return space_update_interval;
}


void MainlineDHT::_SendPing(const NetworkAddress& to)
{
	SendPacket(_PrecomputedMessages._PingMessage, to, PSF_DROPABLE);
	state.PingSent++;
}

void MainlineDHT::_SendFindSelf(const NetworkAddress& to)
{
	SendPacket(_PrecomputedMessages._FindMyselfMessage, to, PSF_DROPABLE);
	state.FindNodeSent++;
}

void MainlineDHT::_SendFindBucket(const DhtAddress& bucket, const NetworkAddress& to)
{
	PacketBuf<> buf;
	UINT len = _PrecomputedMessages._FindMyselfMessage.GetLength();
	memcpy(buf.Claim(len), _PrecomputedMessages._FindMyselfMessage.GetData(), len);
	buf.Commit(len);

	*(DhtAddress*)(buf.GetData() + 9 + 2 + 1 + DHT_ADDRESS_SIZE + 8 + 2 + 1) = bucket;
	SendPacket(buf, to, PSF_DROPABLE);
	state.FindNodeSent++;
}

void MainlineDHT::_SendFindSelf(const rt::Buffer_Ref<NetworkAddress>& to)
{
	for(auto& ip : to)
		_SendFindSelf(ip);
}

void MainlineDHT::_SendFindSelfFromBulitInList()
{
	UINT sent = 0;
	for(UINT i=0; i<sizeofArray(_details::_bootstrap_ip_list); i++)
	{
		DWORD ip = *(DWORD*)&_details::_bootstrap_ip_list[i];

		IPv4 a;
		a.IP = ip;
		a.SetPort(_details::_bootstrap_ip_list[i].port);

		inet::InetAddr addr;
		a.Export(addr);
		if(addr.IsValidDestination())
		{
			NetworkAddress na;
			na.IPv4().Set(addr);
			_SendFindSelf(na);
			sent ++;
		}
	}

	_LOGC("[NET]: Ping "<<sent<<" nodes from built-in bootstrap list");
}

bool MainlineDHT::_SendFindSelfFromFile(LPCSTR fn, NETADDR_TYPE type)
{
	rt::BufferEx<NetworkAddress> list;
	if(_details::LoadNetworkAddressTable(fn, list, type))
		_SendFindSelf(list);
	
	return list.GetSize() > 10;
}

void MainlineDHT::_Bootstrap()
{
	bool bs_avail = false;
	bs_avail = _SendFindSelfFromFile(_pNet->GetCachePath() + "/" DHT_MAIN_ROUTING_BOOTSTRAP_LIST, NADDRT_IPV4);

	if(!bs_avail)
		bs_avail = (int)(!_StockBootstrapFilename.IsEmpty() && _SendFindSelfFromFile(_StockBootstrapFilename));

	if(!bs_avail)
		_SendFindSelfFromBulitInList();
}

void MainlineDHT::_BootstrapIPv6()
{
	if(_SendFindSelfFromFile(_pNet->GetCachePath() + "/" DHT_MAIN_ROUTING_BOOTSTRAP_LIST, NADDRT_IPV6) == 0)
	{
		auto v6_boot = [this](){
			inet::InetAddrV6 addr[2];
			addr[0].SetAddress("dht.libtorrent.org:25401");
			addr[1].SetAddress("dht.transmissionbt.com:6881");
			for(uint32_t i = 0; i < sizeofArray(addr); i++)
			{
				if(addr[i].IsValidDestination())
				{
					NetworkAddress to;
					to.IPv6().Set(addr[i]);
					_SendFindSelf(to);
				}
			}
		};

#if defined(PLATFORM_MAC) || defined(PLATFORM_IOS)
		static os::Thread boot_worker;
		if(!boot_worker.IsRunning())
			boot_worker.Create(v6_boot);
#else
		v6_boot();
#endif
	}
}

bool MainlineDHT::UpdateBootstrapList()
{
	rt::String bslist;
	bslist = _pNet->GetCachePath() + "/" DHT_MAIN_ROUTING_BOOTSTRAP_LIST;
	rt::String list;
	os::File::LoadText(bslist, list);
	rt::hash_set<rt::String, rt::String::hash_compare> old_peers_v4;
	rt::hash_set<rt::String, rt::String::hash_compare> old_peers_v6;
	rt::String_Ref line;
	while(list.GetNextLine(line))
	{	
		if(*line.Begin() == '[')
			old_peers_v6.insert(line);
		else
			old_peers_v4.insert(line);
	}

	DhtSpace::dht_bootstrap_ip_list sort_list_v4;
	if(IsMatureIPv4())
	{
		THREADSAFEMUTABLE_SCOPE(_DhtSpace);
		auto& space = _DhtSpace.GetImmutable();
		if(space.GetNodeCount())
			space.UpdateBootstrapList(old_peers_v4, _Tick, sort_list_v4);
	}

	DhtSpace::dht_bootstrap_ip_list sort_list_v6;
	if(IsMatureIPv6())
	{
		THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
		auto& space = _DhtSpaceIPv6.GetImmutable();
		if(space.GetNodeCount())
			space.UpdateBootstrapList(old_peers_v6, _Tick, sort_list_v6);
	}

	list.Empty();
	if(sort_list_v4.GetSize())
	{
		sort_list_v4.Sort();
		for(UINT i=0; i<DHT_BOOTSTRAP_NODES_MAX && i<sort_list_v4.GetSize(); i++)
			list += tos(sort_list_v4[i].addr) + "\r\n";
	}
	else if(sort_list_v6.GetSize() && !old_peers_v4.empty())
	{
		for(auto& peer : old_peers_v4)
			list += peer + "\r\n";
	}

	if(sort_list_v6.GetSize())
	{
		sort_list_v6.Sort();
		for(UINT i=0; i<DHT_BOOTSTRAP_NODES_MAX && i<sort_list_v6.GetSize(); i++)
			list += tos(sort_list_v6[i].addr) + "\r\n";
	}
	else if(sort_list_v4.GetSize() && !old_peers_v6.empty())
	{
		for(auto& peer : old_peers_v6)
			list += peer + "\r\n";
	}
	if(!list.IsEmpty())
		return os::File::SaveText(bslist, list);

	return false;
}

#if defined(OXD_DUMP_DHT_MESSAGE)
void MainlineDHT::_log_message_write(char tag, LPCSTR bencode, UINT len, const NetworkAddress& peer_addr)
{
	UINT outlen = len*3 + 256;
	LPSTR buf = (LPSTR)alloca(outlen);
	UINT slen = (UINT)
		(	(tag == '>' ? rt::String_Ref() + tag + tag + ' ' + ' ' : rt::String_Ref() + ' ' + ' ' + tag + tag) +
			rt::tos::Number(_log_Message_timer.TimeLapse()).RightAlign(8) + 
			' ' +
			tos(peer_addr) + 
			' '
		).CopyTo(buf);

	if(BencodeToString(bencode, len, buf + slen, &outlen))
	{	slen += outlen;
	}
	else
	{	memcpy(buf + slen, bencode, len);
		slen += len;
		buf[1] = '*';
	}

	*((WORD*)(buf + slen)) = 0xa0d;
	
	_log_Message.Write(buf, slen + 2);
	_log_Message.Flush();
}
#endif

bool MainlineDHT::IsPublicAddressAvailable() const
{
	return _PublicIPv4.GetCount() >= DHT_NODE_EXTERNAL_IP_MATURE;
}

const IPv4& MainlineDHT::GetPublicAddress() const
{
	static const rt::_details::Zeros<sizeof(IPv4)> _;

	if(!_PublicIPv4.IsEmpty())
		return _PublicIPv4.Get(0);
	else
		return (IPv4&)_;
}

bool MainlineDHT::IsPublicAddressAvailableV6() const
{
	return _PublicIPv6.GetCount() >= DHT_NODE_EXTERNAL_IP_MATURE;
}

const IPv6& MainlineDHT::GetPublicAddressV6() const
{
	static const rt::_details::Zeros<sizeof(IPv6)> _;

	if(!_PublicIPv6.IsEmpty())
		return _PublicIPv6.Get(0);
	else
		return (IPv6&)_;
}

void MainlineDHT::_OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx)
{
	if(ctx.pRelayPeer)return;

	os::AtomicAdd(len, &state.TotalRecvBytes);
	os::AtomicIncrement(&state.TotalRecvPacket);

	LPCSTR msgin = (LPCSTR)pData;
	if(len <= 14 || msgin[0] != 'd' || msgin[len-1] != 'e' )
	{
#if defined(OXD_DUMP_DHT_MESSAGE)
		_log_message_write('_', (LPCSTR)pData, len, from);
#endif
        state.RecvCorruptedPacket++;
        return;
	}

	DhtMessageParse::recv_data rd;
	rd.msg = msgin;
	rd.msg_len = len;
	*((DWORD*)rd.trans_token) = *((DWORD*)_TransToken);

    DhtTxReplyContext rc;
	rc.recvctx = &ctx;
	rc.tick = GetTick();

	DhtMessageParse& msg = rc.msg;

	if(msg.ParsePacket(rd, ctx.RecvFrom.Type() == NADDRT_IPV4))
	{
#if defined(OXD_DUMP_DHT_MESSAGE)
		_log_message_write('<', (LPCSTR)pData, len, from);
#endif
#if defined(PLATFORM_DEBUG_BUILD)
		if(ctx.RecvFrom.Type() == NADDRT_IPV4)
		{
			// collect peer versions
			if(msg.fields_parsed&MSGFIELD_PEER_VERSION)
				_PeerVersions.Sample(*((WORD*)msg.version));
			else
				_PeerVersions.Sample(*((WORD*)"??\0\0"));
		}
		else if(ctx.RecvFrom.Type() == NADDRT_IPV6)
		{
			// collect peer versions
			if(msg.fields_parsed&MSGFIELD_PEER_VERSION)
				_PeerVersionsV6.Sample(*((WORD*)msg.version));
			else
				_PeerVersionsV6.Sample(*((WORD*)"??\0\0"));
		}
#endif

		//else // accept only secure DHT nodes
		//{	if(_NodeId_IpRestricted_Init)
		//		return;
		//}

		//if(	(msg.fields_parsed & (MSGFIELD_A_ID|MSGFIELD_R_ID)) &&
		//	msg.a_id == _NodeId
		//)	// refuse to any nodes with duplicated NodeId with us
		//{	return DNOR_ACCEPTED_EXCLUSIVELY;
		//}

		bool validated = false;
		int latency = -1;

		if(	msg.y == 'r' && 
			(msg.fields_parsed&MSGFIELD_TRANSID_REPLY) && 
			(latency = _Tick - msg.reply_transId_tick)>=0 &&
			(msg.fields_parsed&MSGFIELD_R_ID)
		)
		{
			if(msg.r_id == _NodeId)
				return; // skip reflected message

			if(msg.fields_parsed&MSGFIELD_EXTERNAL_IPV4)
			{	
				EnterCSBlock(_PublicIPv4CS);
				_PublicIPv4.Sample(msg.reply_extern_ip_v4, msg.reply_extern_ip_v4.Port()?10:1);
			}

			if(msg.fields_parsed&MSGFIELD_EXTERNAL_IPV6)
			{
				int wei = 1;
				if(!msg.reply_extern_ip_v6.IsTrivial())wei += 100;
				if(msg.reply_extern_ip_v6.Port())wei += 200;

				EnterCSBlock(_PublicIPv6CS);
				_PublicIPv6.Sample(msg.reply_extern_ip_v6, wei);
			}

			//////////////////////////////////////////
			// All reply message
			int verb = msg.reply_transId_verb/2;
			if(verb>=0 && verb<4)
			{
				state.VerbReplyed[verb]++;
			}
			else goto PACKET_CORRUPTED;

			validated = true;
			
			if(msg.reply_transId_txtype == RQTAG_TXTYPE_FINDNODE)
			{
				_FindingNodes.OnReply(rc);
			}
			else if(msg.reply_transId_txtype == RQTAG_TXTYPE_JOINSWARM)
			{
				_JoinSwarms.OnReply(rc);
			}
			else if(msg.reply_transId_txtype == RQTAG_TXTYPE_CONNSWARM)
			{
				_ConnSwarms.OnReply(rc);
			}
		}
		else if(msg.y == 'q')
		{
			//if(!_NodeId_IpRestricted_Init)return;
			//////////////////////////////////////////
			// All query message

			if(msg.fields_parsed&MSGFIELD_A_ID)
			{
				if(msg.a_id == _NodeId)
					return;

				if(msg.q == REQ_GET_PEER && (MSGFIELD_INFOHASH&msg.fields_parsed))
				{
					state.RecvGetPeer++;
					if(_ResponseToGetPeerQueries)
					{	
						bool degard_to_findnode = true;
						{	auto* tx = _JoinSwarms.Get(*msg.info_hash);
							if(tx)
							{	
								tx->OnGetPeers(msg, ctx);
								degard_to_findnode = false;
							}
						}

						if(degard_to_findnode)
						{
							ASSERT(msg.target);
							PacketBuf<> buf;
							if(ctx.RecvFrom.Type() == NADDRT_IPV4)
							{	THREADSAFEMUTABLE_SCOPE(_DhtSpace);
								buf.Commit(ComposeReplyFindNode(buf.Claim(), buf.SIZE, msg.query_transId, msg.query_transId_length, &_DhtSpace.GetImmutable(), *msg.target, ctx.RecvFrom));
							}
							else if(ctx.RecvFrom.Type() == NADDRT_IPV6)
							{	THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
								buf.Commit(ComposeReplyFindNode(buf.Claim(), buf.SIZE, msg.query_transId, msg.query_transId_length, &_DhtSpaceIPv6.GetImmutable(), *msg.target, ctx.RecvFrom));
							}
							SendPacket(buf, ctx.RecvFrom, PSF_DROPABLE|ctx.SendingFlag);
						}
					}
				}
				else if(msg.q == REQ_ANNOUNCE_PEER && (MSGFIELD_INFOHASH&msg.fields_parsed))
				{
					//state.RecvAnnouncePeer++;
					//if(_ResponseToAnounnceQueries)
					//{	auto* tx = _JoinSwarms.Get(*msg.info_hash);
					//	if(tx)
					//	{	
					//		EnterCSBlock(*tx);
					//		tx->OnAnnouncePeer(msg, ctx);
					//	}
					//}
				}
				else 
				if(msg.q == REQ_PING)
				{	// send ping reply
					ASSERT(msg.fields_parsed&MSGFIELD_TRANSID);
					ASSERT(0 == (msg.fields_parsed&MSGFIELD_TRANSID_REPLY));
					ASSERT(msg.query_transId_length <= DHT_MESSAGE_TRANSCATIONID_MAXLEN);

					state.RecvPing++;

					if(MSGFIELD_TARGET&msg.fields_parsed) // extension, ping with target which is from a mature node in a swarm
					{
						auto* tx = _JoinSwarms.Get(*msg.target);
						if(tx)tx->OnPing(msg, ctx);
					}
					else
					{
						PacketBuf<> buf;
						// when receiving a ping query over ipv4, include ipv6 address in reply.
						if(ctx.RecvFrom.Type() == NADDRT_IPV4 && IsPublicAddressAvailableV6())
						{
							buf.Commit(ComposeReplyPing(buf.Claim(), buf.SIZE, msg.query_transId, msg.query_transId_length, GetPublicAddressV6(), ctx.RecvFrom));
						}
						else
						{
							buf.Commit(ComposeReplyPing(buf.Claim(), buf.SIZE, msg.query_transId, msg.query_transId_length, ctx.RecvFrom));
						}

						SendPacket(buf, ctx.RecvFrom, PSF_DROPABLE|ctx.SendingFlag);
					}
				}
				else if(msg.q == REQ_FIND_NODE && msg.fields_parsed&MSGFIELD_TARGET)
				{
					state.RecvFindNode++;
					if(_ResponseToFindQueries)
					{	
						ASSERT(msg.target);
						PacketBuf<> buf;
						if(ctx.RecvFrom.Type() == NADDRT_IPV4)
						{	THREADSAFEMUTABLE_SCOPE(_DhtSpace);
							buf.Commit(ComposeReplyFindNode(buf.Claim(), buf.SIZE, msg.query_transId, msg.query_transId_length, &_DhtSpace.GetImmutable(), *msg.target, ctx.RecvFrom));
						}
						else if(ctx.RecvFrom.Type() == NADDRT_IPV6)
						{	THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
							buf.Commit(ComposeReplyFindNode(buf.Claim(), buf.SIZE, msg.query_transId, msg.query_transId_length, &_DhtSpaceIPv6.GetImmutable(), *msg.target, ctx.RecvFrom));
						}
						SendPacket(buf, ctx.RecvFrom, PSF_DROPABLE|ctx.SendingFlag);
					}
				}
				else goto PACKET_CORRUPTED;

				validated = true;
			}
			else goto PACKET_CORRUPTED;
		}
		else if(msg.y == 'e')
		{
			state.RecvError++;
		}
		else goto PACKET_CORRUPTED;

		if(validated)
		{
			// collect nodes for DHT update
			if(ctx.RecvFrom.Type() == NADDRT_IPV4)
				_CollectDiscoveredNodes(msg, ctx.RecvFrom, (float)latency);
			else if(ctx.RecvFrom.Type() == NADDRT_IPV6)
				_CollectDiscoveredNodesIPv6(msg, ctx.RecvFrom, (float)latency);
		}

		return;
	}
	else
	{
#if defined(OXD_DUMP_DHT_MESSAGE)
		_log_message_write('/', (LPCSTR)pData, len, from);
#endif
		//_LOGC("RECV UNK FROM: "<<inet::InetAddr(from.GetIPv4_Port(), from.GetIPv4_IP()));
	}
	
PACKET_CORRUPTED:
	state.RecvCorruptedPacket++;
	return;
}

void MainlineDHT::_LogMsg(const DhtMessageParse& msg, const NetworkAddress& from, UINT len)
{
	return;

	static const LPCSTR verb[4] = { "ping", "findnode", "getpeer", "announce" };
	static const LPCSTR type[4] = { "TX-Routing", "TX-Node", "TX-Peers", "TX-Swarm" };

	if(msg.y == 'r')
	{
		UINT t = msg.reply_transId_txtype>>4;
		UINT v = (msg.reply_transId_verb&RQTAG_MASK_VERB)>>1;

		_LOG_VERBOSE(	"DHT-Ack: "<<
						(t<4?type[t]:(LPCSTR)(rt::SS("TX-(") + t + ")"))<<'/'<<
						(v<4?verb[v]:(LPCSTR)(rt::SS("[") + v + "]"))<<'/'<<(msg.reply_transId_tx)<<' '<<
						len<<"B <"<<tos(from)<<'>'
		);
	}
	else
	{	rt::String_Ref q;
		switch(msg.q)
		{	case REQ_PING: q = verb[0]; break;
			case REQ_FIND_NODE: q = verb[1]; break;
			case REQ_GET_PEER: q = verb[2]; break;
			case REQ_ANNOUNCE_PEER: q = verb[3]; break;
			default: q = rt::String_Ref((LPCSTR)&msg.q, 4); break;
		}
				
		_LOG_VERBOSE("DHT-Req: "<<q<<' '<<len<<"B <"<<tos(from)<<'>');
	}
}

void MainlineDHT::_CollectDiscoveredNodes(const DhtMessageParse& msg, const NetworkAddress& from, float latency)
{
	ASSERT(from.Type() == NADDRT_IPV4);
	if(_NodeDiscovered.GetSize() >= DHT_SPACE_DISCOVER_QUEUE_MAXSIZE)
		return;

	THREADSAFEMUTABLE_SCOPE(_DhtSpace);
	auto& dht = _DhtSpace.GetImmutable();

	// Introduced nodes by find node/get node
	if((msg.fields_parsed&MSGFIELD_NODES) && msg.nodes_size)
	{
		for(UINT i=0;i<msg.nodes_size;i++)
		{	
			DhtSpace::dht_node_discovered n;

			{	
				//if(msg.nodes[i].DhtAddress == _NodeId)continue; // eliminate nodes with duplicated ID
				UINT node_index = dht.FindNode(msg.nodes[i].DhtAddress);
				//if(node_index != dht.GetNodeCount())continue;
				n.bucket = _GetBucketIndex(msg.nodes[i].DhtAddress);
				if(n.bucket < DHT_BUCKET_DISTANCE_BASE || !dht.GetBucket(n.bucket).IsAcceptingNewNode())continue;
			}

			n.nodeinfo.DhtAddress = msg.nodes[i].DhtAddress;
			n.nodeinfo.NetAddress.IPv4() = msg.nodes[i].NetAddress;
			n.latency = -1;
			n.timestamp = _Tick;
			n.is_new = true;

			_NodeDiscovered.Push(n);
		}
	}
				
	DhtSpace::dht_node_discovered n;

	n.bucket = _GetBucketIndex(msg.r_id);
	if(n.bucket < DHT_BUCKET_DISTANCE_BASE)return;

	n.is_new = dht.FindNode(msg.r_id) == dht.GetNodeCount();
	if(n.is_new && !dht.GetBucket(n.bucket).IsAcceptingNewNode())return;

	n.nodeinfo.DhtAddress = msg.r_id;
	n.nodeinfo.NetAddress = from;
	n.latency = (int)latency;
	n.timestamp = _Tick;
	_NodeDiscovered.Push(n);
}

void MainlineDHT::_CollectDiscoveredNodesIPv6(const DhtMessageParse& msg, const NetworkAddress& from, float latency)
{
	ASSERT(from.Type() == NADDRT_IPV6);
	if(_NodeDiscoveredIPv6.GetSize() >= DHT_SPACE_DISCOVER_QUEUE_MAXSIZE)
		return;

	THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
	auto& dht = _DhtSpaceIPv6.GetImmutable();

	// Introduced nodes by find node/get node
	if((msg.fields_parsed&MSGFIELD_NODES6) && msg.nodes6_size)
	{
		for(UINT i=0;i<msg.nodes6_size;i++)
		{	
			DhtSpace::dht_node_discovered n;

			{	
				//if(msg.nodes[i].DhtAddress == _NodeId)continue; // eliminate nodes with duplicated ID
				UINT node_index = dht.FindNode(msg.nodes6[i].DhtAddress);
				//if(node_index != dht.GetNodeCount())continue;
				n.bucket = _GetBucketIndex(msg.nodes6[i].DhtAddress);
				if(n.bucket < DHT_BUCKET_DISTANCE_BASE || !dht.GetBucket(n.bucket).IsAcceptingNewNode())continue;
			}

			n.nodeinfo.DhtAddress = msg.nodes6[i].DhtAddress;
			n.nodeinfo.NetAddress.IPv6() = msg.nodes6[i].NetAddress;
			n.latency = -1;
			n.timestamp = _Tick;
			n.is_new = true;

			_NodeDiscoveredIPv6.Push(n);
		}
	}
				
	DhtSpace::dht_node_discovered n;

	n.bucket = _GetBucketIndex(msg.r_id);
	if(n.bucket < DHT_BUCKET_DISTANCE_BASE)return;

	n.is_new = dht.FindNode(msg.r_id) == dht.GetNodeCount();
	if(n.is_new && !dht.GetBucket(n.bucket).IsAcceptingNewNode())return;

	n.nodeinfo.DhtAddress = msg.r_id;
	n.nodeinfo.NetAddress = from;
	n.latency = (int)latency;
	n.timestamp = _Tick;
	_NodeDiscoveredIPv6.Push(n);
}

bool MainlineDHT::InvitePeer(UINT swarm_id, const NetworkAddress& ip, bool conn_swarm)
{
	if(conn_swarm)
	{
		if(_ConnSwarms.Get(swarm_id) != nullptr)
		{
			_ConnSwarms.Get(swarm_id)->InvitePeer(ip, false);
			return true;
		}
	}
	else
	{
		if(_JoinSwarms.Get(swarm_id) != nullptr)
		{
			_JoinSwarms.Get(swarm_id)->InvitePeer(ip, true);
			return true;
		}
	}

	return false;
}

void MainlineDHT::JsonifySwarms(rt::Json& json) const
{
	json.Array();

	if(_JoinSwarms.GetSize())
	{
		_JoinSwarms.Jsonify(json.ScopeMergingArray());
	}

	if(_ConnSwarms.GetSize())
	{
		_ConnSwarms.Jsonify(json.ScopeMergingArray());
	}
}

void MainlineDHT::GetStateReport(rt::String& out)
{
    static const char LN = '\n';

	out+= rt::SS("*** DHT Messaging ***\n") +
		  rt::SS("NodeId:") + tos(_NodeId) +
		  LN +
		  rt::SS("REQ: P(") + state.PingReplyed + '/' + state.PingSent + ')' + ' ' + 
			   rt::SS("F(") + state.FindNodeReplyed + '/' + state.FindNodeSent + ')' + ' ' + 
			   rt::SS("G(") + state.GetPeerReplyed + '/' + state.GetPeerSent + ')' + ' ' + 
			   rt::SS("A(") + state.AnnouncePeerReplyed + '/' + state.AnnouncePeerSent + ')' + ' ' + 
		  LN;

	out+= rt::SS("RCV: P(") + state.RecvPing + ") F(" + state.RecvFindNode + ") G(" + state.RecvGetPeer + ") A(" + state.RecvAnnouncePeer + ") E(" + 
		  state.RecvError + ") D(" + state.RecvDroppedPacket + ") C(" + state.RecvCorruptedPacket + ')' +
		  LN;

	ULONGLONG total_recv = state.TotalRecvBytes;
	ULONGLONG total_sent = state.TotalSentBytes;

	out+= rt::String_Ref() + 
		  rt::SS("I/O: ") + 
		  rt::tos::FileSize<true,true>(total_recv) + rt::SS(" + ") + 
		  rt::tos::FileSize<true,true>(total_sent) + rt::SS(" = ") +
		  rt::tos::FileSize<true,true>(total_recv+total_sent) + 
		  LN +
		  rt::SS("PKT: ") + 
		  state.TotalRecvPacket + rt::SS(" + ") + 
		  state.TotalSentPacket + rt::SS(" = ") + 
		  (state.TotalRecvPacket + state.TotalSentPacket) + 
		  LN +
		  rt::SS("B/W: ") +
		  rt::tos::FileSize<true,true>(total_recv/(1 + _pNet->GetUpTime()/1000)) + rt::SS("/s + ") +
		  rt::tos::FileSize<true,true>(total_sent/(1 + _pNet->GetUpTime()/1000)) + rt::SS("/s") +
		  LN; 

	out += rt::SS("Ext-IPv4: ");
        {
			for(UINT i=0; i<_PublicIPv4.GetCapacity(); i++)
			{
				UINT co = _PublicIPv4.GetCount(i);
				if(co == 0)break;
				if(i)out += ", ";
				out += tos(_PublicIPv4.Get(i)) + '/' + co;
			}
			out += LN;
		}

	out += rt::SS("Ext-IPv6: ");
		{
			for(UINT i=0; i<_PublicIPv6.GetCapacity(); i++)
			{
				UINT co = _PublicIPv6.GetCount(i);
				if(co == 0)break;
				if(i)out += "\n          ";
				out += tos(_PublicIPv6.Get(i)) + '/' + co;
			}
			out += LN;
		}
	out += LN;

#if defined(PLATFORM_DEBUG_BUILD)
#define FIX_VERNAME(ver)	if((ver)[0] < ' ')(ver)[0] = '?';	\
							if((ver)[1] < ' ')(ver)[1] = '?';

		out += rt::SS("Versions: ");
		for(UINT i=0;i<_PeerVersions.GetSize();i++)
		{	WORD ver;
			int count;
			if(_PeerVersions.Get(i, &ver, &count))
			{	FIX_VERNAME((LPSTR)&ver);
				out += rt::String_Ref((LPSTR)&ver,2) + '/' + count + ' ';
			}else break;
		}
		out += LN;

		if(_PeerVersionsV6.GetSize())
		{
			out += rt::SS("   (IPv6) ");
			for(UINT i = 0; i < _PeerVersionsV6.GetSize(); i++)
			{
				WORD ver;
				int count;
				if(_PeerVersionsV6.Get(i, &ver, &count))
				{	FIX_VERNAME((LPSTR)&ver);
					out += rt::String_Ref((LPSTR)&ver, 2) + '/' + count + ' ';
				}
				else break;
			}
			out += LN;
		}
#endif
/*
		out += rt::SS("Secured Versions: ");
		for(UINT i=0;i<_SecurePeerVersions.GetSize();i++)
		{	WORD ver;
			int count;
			if(_SecurePeerVersions.Get(i, &ver, &count))
			{	FIX_VERNAME((LPSTR)&ver);
				out += rt::String_Ref((LPSTR)&ver,2) + '/' + count + ' ';
			}else break;
		}
		out += LN;

		if(_SecurePeerVersionsV6.GetSize())
		{
			out += rt::SS("           (IPv6) ");
			for(UINT i = 0; i < _SecurePeerVersionsV6.GetSize(); i++)
			{
				WORD ver;
				int count;
				if(_SecurePeerVersionsV6.Get(i, &ver, &count))
				{	FIX_VERNAME((LPSTR)&ver);
					out += rt::String_Ref((LPSTR)&ver, 2) + '/' + count + ' ';
				}
				else break;
			}
			out += LN;
		}
#undef FIX_VERNAME
*/
	{
		THREADSAFEMUTABLE_SCOPE(_DhtSpace);
		auto& space = _DhtSpace.GetImmutable();
		if(space.GetNodeCount())
		{
			out += rt::SS("\n*** Primary IPv4 DHT Space ***\n");
			space.GetStateReport(out,_Tick);
		}
		else
		{	out += rt::SS("\nPrimary IPv4 DHT Space is empty") + LN;
		}
	}

	{
		THREADSAFEMUTABLE_SCOPE(_DhtSpaceIPv6);
		auto& space = _DhtSpaceIPv6.GetImmutable();
		if(space.GetNodeCount())
		{
			out += rt::SS("\n*** Primary IPv6 DHT Space ***\n");
			space.GetStateReport(out,_Tick);
		}
		else
		{	out += rt::SS("\nPrimary IPv6 DHT Space is empty") + LN;
		}
	}

	if(_FindingNodes.GetSize())
	{
		out += "\n*** Finding Node Transcations ***\n";
		_FindingNodes.GetStateReport(out, _Tick);
	}

	if(_JoinSwarms.GetSize())
	{
		out += "\n*** Swarm-Joining Transcations ***\n";
		_JoinSwarms.GetStateReport(out, _Tick);
	}

	if(_ConnSwarms.GetSize())
	{
		out += "\n*** Swarm-Connecting Transcations ***\n";
		_ConnSwarms.GetStateReport(out, _Tick);
	}
}

void MainlineDHT::GetState(NetworkState_DHT& ns) const
{
	ns.DHT_PublicIPv4 = GetPublicAddress();
	ns.DHT_PublicIPv6 = GetPublicAddressV6();

	THREADSAFEMUTABLE_SCOPE(_DhtSpace);
	_DhtSpace.GetImmutable().GetState(ns, _Tick);
	
	ns.DHT_InboundDataSize = (ULONGLONG)state.TotalRecvBytes;
	ns.DHT_OutbounDatadSize = (ULONGLONG)state.TotalSentBytes;
	ns.DHT_InboundPacketNum = state.TotalRecvPacket;
	ns.DHT_OutboundPacketNum = state.TotalSentPacket;
	
	ns.DHT_PingSent				= state.PingSent;
	ns.DHT_FindNodeSent			= state.FindNodeSent;
	ns.DHT_GetPeerSent			= state.GetPeerSent;
	ns.DHT_AnnouncePeerSent		= state.AnnouncePeerSent;
	
	ns.DHT_PingReplyed			= state.PingReplyed;
	ns.DHT_FindNodeReplyed		= state.FindNodeReplyed;
	ns.DHT_GetPeerReplyed		= state.GetPeerReplyed;
	ns.DHT_AnnouncePeerReplyed	= state.AnnouncePeerReplyed;
	
	ns.DHT_RecvPing				= state.RecvPing;
	ns.DHT_RecvFindNode			= state.RecvFindNode;
	ns.DHT_RecvGetPeer			= state.RecvGetPeer;
	ns.DHT_RecvAnnouncePeer		= state.RecvAnnouncePeer;
	ns.DHT_RecvError			= state.RecvError;
	ns.DHT_RecvDroppedPacket	= state.RecvDroppedPacket;
	ns.DHT_RecvCorruptedPacket	= state.RecvCorruptedPacket;
}

const DhtAddress& MainlineDHT::GetSwarmAddress(UINT swarm_id) const
{
	static const rt::_details::Zeros<sizeof(DhtAddress)> _;

	auto* s = _JoinSwarms.Get(swarm_id);
	return s?s->GetTarget():(const DhtAddress&)_;
}

} // namespace upw
