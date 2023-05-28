#include "../../externs/miniposix/core/ext/ipp/ipp_core.h"
#include "dht_tx_swarm.h"


namespace upw
{

DhtTxSwarm::DhtTxSwarm(const DhtAddress& target, 
                                   MainlineDHT& dht, 
								   UINT expected_num, 
								   const DhtAddress* nodeid, 
								   DWORD app, 
                                   const DhtAddress* private_secret,
								   const rt::String_Ref& boot_file)
	:DhtTxRecentHosts(dht)
{
	ASSERT(expected_num);

	_TX = 0;  // will be assigned by DhtTxns::Create
	_TX_TYPE = 0;
	_Target = target;
	_AppTag = app;
	_ExpectedNum = expected_num;

	if(nodeid)
		_NodeId = *nodeid;
	else
		_NodeId = _DHT.GetNodeId();

	if(private_secret)
	{
		_IsPrivateSwarm = true;
		_PrivateSwarmSecret = *private_secret;
	}

	rt::Randomizer((UINT)os::Timestamp::Get()).Randomize(_SecureL1Mask)
											  .Randomize(_SecureL1Orig);

	_StockBootstrapFilename = boot_file;

	{	UINT len = offsetof(PeerList, Peers) + sizeof(NetworkAddress)*expected_num*2;

		_OutputPeers_Front = (PeerList*)_Malloc8AL(BYTE, len);
		rt::Zero(*_OutputPeers_Front);

		_OutputPeers_Back = (PeerList*)_Malloc8AL(BYTE, len);
		rt::Zero(*_OutputPeers_Back);
	}
}

DhtTxSwarm::~DhtTxSwarm()
{
	_SafeFree8AL(_OutputPeers_Front);
	_SafeFree8AL(_OutputPeers_Back);
}

ULONGLONG DhtTxSwarm::_GetPrivateSwarmPacketNum(const IPv4& from) const
{
	ASSERT(_IsPrivateSwarm);
	ULONGLONG crc = ipp::crc64(&from, sizeof(IPv4), *(ULONGLONG*)&_PrivateSwarmSecret);
	return ipp::crc64(&_PrivateSwarmSecret, sizeof(_PrivateSwarmSecret), crc);
}

ULONGLONG DhtTxSwarm::_GetPrivateSwarmPacketNum(const IPv6& from) const
{
	ASSERT(_IsPrivateSwarm);
	ULONGLONG crc = ipp::crc64(&from, sizeof(IPv6), *(ULONGLONG*)&_PrivateSwarmSecret);
	return ipp::crc64(&_PrivateSwarmSecret, sizeof(_PrivateSwarmSecret), crc);
}

void DhtTxSwarm::_AppendPrivateSwarmPacketNum(PacketBuf<>& buf, NETADDR_TYPE type) const
{
	ULONGLONG pnum;
	if(type == NADDRT_IPV4)
		pnum = _GetPrivateSwarmPacketNum(_DHT.GetPublicAddress());
	else if(type == NADDRT_IPV6)
		pnum = _GetPrivateSwarmPacketNum(_DHT.GetPublicAddressV6());
	else
		return;

	buf << (rt::SS("4:pspn8:") + rt::DS(&pnum, 8));
}

void DhtTxSwarm::_PrintPeers(bool forward, const rt::BufferEx<Node>& peers, rt::String& out) const
{
	UINT tick = _DHT.GetTick();
	for(UINT i=0; i<peers.GetSize(); i++)
	{
		auto& p = peers[i];
		if(forward)
			out += "=>> ";
		else if(p.IsBackwardEstablished(tick))
			out += "<<= ";
		else
			out += "<-- ";

		out += tos(p.DhtAddress).SubStr(0, 8) + ' ' + 
				(p.IpRestrictVerified()?'[':'(') + p.PeerDesc.GetNodeName() + (p.IpRestrictVerified()?']':')') + ':';

		if(p.PeerDesc.HasHOB())out += 'O';
		if(p.PeerDesc.HasDHT())out += 'H';
		if(p.PeerDesc.HasLSM())out += 'L';
		if(p.PeerDesc.HasPBC())
		{	
			if(p.Flag&NODE_CLOAKED_MYIP)
				out += 'B';
			else
				out += 'b';
		}
		if(p.PeerDesc.HasGDP())out += 'G';
		if(p.PeerDesc.HasGNT())out += 'T';

		out +=	rt::SS(" (") + rt::tos::TimeSpan<false>(p.Age(tick)*NET_TICK_UNIT) + ") "
				"LTNC:" + (int)(p.latency_average*NET_TICK_UNIT_FLOAT + 0.5f) + rt::SS(" TTL:");

		if(!p.IsForward())
			out += rt::SS() + p.BackwardTTL(tick) + '/';

		out += rt::SS() + p.TTL(tick) + '/' + p.Lifetime() + '\n';

		out +=  rt::SS("    IP: ") + tos(p.NetAddress);
		if(!p.ExternalIP.IsEmpty())
			out += rt::SS(" --> ") + tos(p.ExternalIP);
		out += '\n';

		if(!p.AlternativeIP.IsEmpty())
		{
			out += rt::SS("    ATL: ") + tos(p.AlternativeIP) + '\n';
		}
	}
}

void DhtTxSwarm::_UpdateNodeAuxInfo(DhtTxSwarm::Node& n, const DhtMessageParse& msg, const NetworkAddress& from)
{
	if(msg.fields_parsed&MSGFIELD_NODEDESC)
		n.PeerDesc = msg.node_desc;

	// swap node NetAddress and AlternativeIP
	if(n.NetAddress.IsIPv4() && from.IsIPv6())
	{
		n.AlternativeIP = n.NetAddress;
		n.NetAddress = from;
		n.ExternalIP.Empty();
	}
	else if(n.NetAddress.IsIPv6() && from.IsIPv4())
	{
		if(!_DHT.IsPublicAddressAvailableV6() || !(msg.fields_parsed&MSGFIELD_ALTERNATIVE_IPV6) ||
		  ((msg.fields_parsed&MSGFIELD_ALTERNATIVE_IPV6) && n.NetAddress.IPv6() != msg.alternative_ip_v6))
		{
			n.AlternativeIP = n.NetAddress;
			n.NetAddress = from;
			n.ExternalIP.Empty();
		}
	}

	if(from.IsIPv4() && (msg.fields_parsed&MSGFIELD_EXTERNAL_IPV4) && n.NetAddress.IsIPv4())
	{
		n.ExternalIP = msg.reply_extern_ip_v4;
	}
	else if(from.IsIPv6() && (msg.fields_parsed&MSGFIELD_EXTERNAL_IPV6) && n.NetAddress.IsIPv6())
	{
		n.ExternalIP = msg.reply_extern_ip_v6;
	}

	if(msg.fields_parsed&MSGFIELD_ALTERNATIVE_IPV4 && n.NetAddress.IsIPv6())
		n.AlternativeIP = msg.alternative_ip_v4;

	if(msg.fields_parsed&MSGFIELD_ALTERNATIVE_IPV6 && n.NetAddress.IsIPv4())
		n.AlternativeIP = msg.alternative_ip_v6;

	if(msg.cip_v4)
	{
		if((msg.fields_parsed&MSGFIELD_ALTERNATIVE_IPV4) && n.ExternalIP.IsIPv4())
		{
			n.EncryptIPv4 = *msg.cip_v4;
			n.Flag |= NODE_CLOAKED_MYIP;
		}
		else if((msg.fields_parsed&MSGFIELD_ALTERNATIVE_IPV6) && n.ExternalIP.IsIPv6())
		{
			n.EncryptIPv6 = *msg.cip_v6;
			n.Flag |= NODE_CLOAKED_MYIP;
		}
	}
}

void DhtTxSwarm::_RemoveDuplicatedInsecurePeers(rt::BufferEx<DhtTxSwarm::Node>& swarm_peers, UINT open, UINT q, NETADDR_TYPE net_type, bool is_forward, const DhtAddress& dht_addr)
{
	for(; q<swarm_peers.GetSize(); q++)
	{
		if(!swarm_peers[q].IpRestrictVerified() && 
			swarm_peers[q].IsForward() == is_forward &&
			swarm_peers[q].DhtAddress == dht_addr
		)
		{	RejectPeer(swarm_peers[q].NetAddress);
			continue; // remove
		}

		swarm_peers[open++] = swarm_peers[q];
	}
	swarm_peers.ShrinkSize(open);
}

void DhtTxSwarm::_AppendAltIp(const NetworkAddress& peer, PacketBuf<>& buf) const
{
	if(peer.IsIPv4() && _DHT.IsPublicAddressAvailableV6())
	{
		auto& ip = _DHT.GetPublicAddressV6();
		if(!ip.IsTrivial())
			buf << rt::SS("5:altip") + sizeof(IPv6) + ':' + rt::DS(ip);
	}

	if(peer.IsIPv6() && _DHT.IsPublicAddressAvailable())
		buf << rt::SS("5:altip") + sizeof(IPv4) + ':' + rt::DS(_DHT.GetPublicAddress());
}

void DhtTxSwarm::_AppendCloakedIp(const NetworkAddress& to, PacketBuf<>& buf) const
{
	if(to.IsIPv4())
	{
		CloakedIPv4 cip;
		cip = to.IPv4();
		_DHT.GetCore()->CloakIP(cip);

		buf << (rt::SS("4:cip4") + sizeof(cip) + ':' + rt::DS(cip));
	}
	else
	{
		ASSERT(to.IsIPv6());
		CloakedIPv6 cip;
		cip = to.IPv6();
		_DHT.GetCore()->CloakIP(cip);

		buf << (rt::SS("4:cip6") + sizeof(cip) + ':' + rt::DS(cip));
	}
}

void DhtTxSwarm::InvitePeer(const NetworkAddress& ip, bool in_list) const
{
	_SendContactMessage(ip, true, in_list, PSF_NORMAL);
}

void DhtTxSwarm::_SendContactMessage(const NetworkAddress& to, bool no_discover, bool in_list, PACKET_SENDING_FLAG flag) const
{
	bool is_join = RQTAG_TXTYPE_JOINSWARM == _TX_TYPE;

	PacketBuf<> buf;
	if(no_discover)
	{
		_DHT.state.PingSent++;
  
		buf <<
		(	rt::SS("d1:ad") +
				rt::SS("2:id") +	 DHT_ADDRESS_SIZE + ':' + rt::DS(&_NodeId, DHT_ADDRESS_SIZE) +
				rt::SS("6:target") + DHT_ADDRESS_SIZE + ':' + rt::DS(&GetTarget(), DHT_ADDRESS_SIZE) +
				rt::SS("e1:q4:ping1:t9:") + ((char)(_TX_TYPE | RQTAG_VERB_PING)) +
				rt::DS(_DHT._TransToken, 2) +  /* WORD Transaction id for better security (reply message should be received from nodes we contacted*/
				rt::DS(&_TX, 2) +
				rt::DS(&_DHT._Tick, 4) + /* UINT send _Tick, for estimating round trip latency */
				rt::SS("1:v4:") + rt::DS(&_DHT._DhtVer, 4) +
				rt::SS("3:app4:") + rt::DS(&_AppTag, 4) +
				rt::SS("2:nd") + rt::SS("12:") + rt::DS(&_DHT.GetCore()->GetNodeDesc(), 12)
		);

		if(in_list && is_join)
			_AppendCloakedIp(to, buf);

		static_assert(sizeof(_DHT.GetCore()->GetNodeDesc()) == 12, "NetworkNodeDesc should be sized as 12");
	}
	else
	{
		_DHT.state.GetPeerSent++;

		buf << 
		(	rt::SS("d") +
				rt::SS("1:ad") +
					rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(&_NodeId, DHT_ADDRESS_SIZE) +
					rt::SS("9:info_hash") + DHT_ADDRESS_SIZE + ':' + rt::DS(&GetTarget(), DHT_ADDRESS_SIZE)
		);

		if(is_join)
		{
			buf << (rt::SS("4:swmb") + rt::SS("1:1"));
			if(in_list)
				_AppendCloakedIp(to, buf);
		}

		buf <<
		(		rt::SS("e") +
				rt::SS("1:q") + rt::SS("9:get_peers") + 
				rt::SS("1:t") + rt::SS("9:") + ((char)(_TX_TYPE|RQTAG_VERB_GETPEERS)) + 
				rt::DS(_DHT._TransToken, 2) +  /* WORD Transaction id for better security (reply message should be received from nodes we contacted*/
				rt::DS(&_TX, 2) +
				rt::DS(&_DHT._Tick, 4) + /* UINT send _Tick, for estimating round trip latency */
				rt::SS("1:v4:") + rt::DS(&_DHT._DhtVer, 4) +
				rt::SS("3:app4:") + rt::DS(&_AppTag, 4) +
				rt::SS("2:nd") + rt::SS("12:") + rt::DS(&_DHT.GetCore()->GetNodeDesc(), 12)
		);
	}

	if(_IsPrivateSwarm)
		_AppendPrivateSwarmPacketNum(buf, to.Type());

	_AppendAltIp(to, buf);

	buf << 	rt::SS("1:y1:qe");

	ASSERT(buf.GetLength());
	_DHT.SendPacket(buf, to, PSF_DROPABLE|flag);
}

bool DhtTxSwarm::_SendContactMessageFromBootstrapFile() const
{
	ext::fast_map<NetworkAddress, NetworkAddress> list;
	if(!_StockBootstrapFilename.IsEmpty())
	{
		if(_details::LoadSwarmNetworkAddressTable(_StockBootstrapFilename, list))
		{
			_LOGC("[NET]: Swarm bootstrap by "<<list.size()<<" peers ("<<_StockBootstrapFilename.GetFileName()<<')');
			for(auto& item : list)
			{
				_SendContactMessage(item.first, false, true, PSF_OBFUSCATION|PSF_DROPABLE);
				//AddQueried(item.first);
			}

			return true;
		}
	}

	return false;
}

float DhtTxSwarm::_PingScan(bool no_discover, bool force, rt::BufferEx<Node>& peers) const
{
	int tick = (int)_DHT.GetTick();
    UINT open = 0;
    float latency = 0;
        
    for(UINT i=0; i<peers.GetSize(); i++)
    {
        auto& p = peers[i];

		if(!_DHT.GetCore()->IsNetworkTimeStablized())
		{
			_SendContactMessage(p.NetAddress, false, true, PSF_DROPABLE|PSF_OBFUSCATION);
		}
		else
		{
			int lapsed = tick - p.last_recv;
			if(lapsed < DHT_SWARM_PING_INTERVAL)
			{
				if( lapsed >= DHT_SWARM_PING_INTERVAL*3/4 &&
					!_DHT.GetCore()->IsNetworkTimeStablized() // request for time samples
				)
				{   _SendContactMessage(p.NetAddress, false, true, PSF_DROPABLE|PSF_OBFUSCATION);
					p.last_sent = tick;
				}
			}
			else if(p.TTL(tick) > 0)
			{
				if(p.IsForward() || (_TX_TYPE == RQTAG_TXTYPE_JOINSWARM && (!p.IsBackwardEstablished(tick) ||
				  (_DiscoveredForward == 0 && !no_discover))))
				//if(p.IsForward() || !p.IsBackwardEstablished(tick) || !no_discover)
				{
					_SendContactMessage(p.NetAddress, no_discover, true, PSF_DROPABLE|PSF_OBFUSCATION);
					p.last_sent = tick;
				}
			}
			else
			{
				_InvokePeerEvent(DHT_SWARM_DROPPING, p);
				if(!force)continue; // peer is gone
			}
		}

        p.last_sent = tick;
        latency += p.latency_average;
        if(open != i)peers[open] = p;

        open++;
    }

    peers.ShrinkSize(open);
    return open?latency/open:-1;
};


void DhtTxSwarm::_StartActiveDiscovery(bool is_mature)
{
	ASSERT(IsLockedByCurrentThread());
	ASSERT(_ActiveDiscoveringStartTime == 0);

	_ActiveDiscoveringStartTime = os::Timestamp::Get();
	_ActiveDiscoveredByStockBootstrapList = false;

	DhtTxRecentHosts::SetCapacityHint(_ExpectedNum*DHT_SWARM_DISCOVERY_HOSTS_MAX*3/2);
	DhtTxRecentHosts::SetHardLimit(_ExpectedNum*DHT_SWARM_DISCOVERY_HOSTS_MAX);
	DhtTxRecentHosts::SetRecentPeriod(3600000);

	bool pinged = false;

	// ping from peer cache
	{
		auto& addr = this->GetTarget();
		rt::String fn = _DHT.GetCore()->GetCachePath() + '/' + rt::tos::Base32LowercaseOnStack<>(addr) + DHT_SWARM_BOOTSTRAP_EXTNAME;

		ext::fast_map<NetworkAddress, NetworkAddress> list;
		if(_details::LoadSwarmNetworkAddressTable(fn, list))
		{
			for(auto& item : list)
			{
				_SendContactMessage(item.first, false, true, PSF_OBFUSCATION|PSF_DROPABLE);
				AddQueried(item.first);
				if(!item.second.IsEmpty())
				{
					_SendContactMessage(item.second, false, true, PSF_OBFUSCATION | PSF_DROPABLE);
					AddQueried(item.second);
				}
				pinged = true;
			}
		}
	}

	// find nodes
	{
		DhtSpace::_CollectedNode nodes[DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE];
		UINT co = _DHT.GetClosestNodes(GetTarget(), nodes, sizeofArray(nodes));
		if(!co && !is_mature) {
			_DHT.IterateUpdateDhtSpace();
			co = _DHT.GetClosestNodes(GetTarget(), nodes, sizeofArray(nodes));
		}

		if(co)
		{
			for(UINT i=0; i<co; i++)
			{
				_SendContactMessage(nodes[i].node.NetAddress, false, false, PSF_DROPABLE);
				AddQueried(nodes[i].node.NetAddress);
				pinged = true;
			}
		}
	}

	// find ipv6 nodes
	{
		DhtSpace::_CollectedNode nodes[DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE];
		UINT co = _DHT.GetClosestNodesIPv6(GetTarget(), nodes, sizeofArray(nodes));
		if(!co && !is_mature) {
			_DHT.IterateUpdateDhtSpaceIPv6();
			co = _DHT.GetClosestNodesIPv6(GetTarget(), nodes, sizeofArray(nodes));
		}

		if(co)
		{
			for(UINT i=0; i<co; i++)
			{
				_SendContactMessage(nodes[i].node.NetAddress, false, false, PSF_DROPABLE);
				AddQueried(nodes[i].node.NetAddress);
				pinged = true;
			}
		}
	}

	if(!pinged)
	{
		_ActiveDiscoveredByStockBootstrapList = true;
		_SendContactMessageFromBootstrapFile();
	}	
}

void DhtTxSwarm::Bootstrap()
{
	ASSERT(!IsLockedByCurrentThread());

	EnterCSBlock(*this);
	_StartActiveDiscovery(false);
}

void DhtTxSwarm::Jsonify(rt::Json& json) const
{
	json.Object((
		J(addr) = tos(_Target),
		J(id) = _TX,
		J(private) = _IsPrivateSwarm
	));
}

} // namespace upw
