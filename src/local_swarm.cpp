#include "../externs/miniposix/core/ext/ipp/ipp_core.h"
#include "netsvc_core.h"
#include "local_swarm.h"
#include "./dht/dht.h"


namespace upw
{

ULONGLONG LocalSwarm::_AppName = 0;

void LocalSwarm::SetMessageAppName(const rt::String_Ref& name)
{
	_AppName = os::crc64(name.Begin(), name.GetLength(), 0x80328032);
}

LocalSwarm::LocalSwarm(NetworkServiceCore* p, const NetworkNodeDesc& nd, UINT expected_num)
	:_pNet(p)
{
	_bSwarmPeersDirty = false;
	_pNodeDesc = &nd;
	_BroadcastAddressCount = 0;

	_pOutputPeers_Front = (LocalPeerList*)_Malloc32AL(BYTE, offsetof(LocalPeerList, Peers) + sizeof(NetworkAddress)*8);
	_pOutputPeers_Back = (LocalPeerList*)_Malloc32AL(BYTE, offsetof(LocalPeerList, Peers) + sizeof(NetworkAddress)*8);
	_pOutputPeers_Front->Reserved = 8;
	_pOutputPeers_Back->Reserved = 8;
	_pOutputPeers_Front->Count = 0;
	_pOutputPeers_Back->Count = 0;

	_LocalDiscoveryPort = DHT_LOCALSWARM_DISCOVERY_PORT_MIN;
	__LocalSwarmPeerScanBase = 0;
	_ActiveSubnetSwarmPeersCount = 0;

	bool ret = _LocalDiscoveryThread.Create(
					[this](){
						_LocalDiscoveryFunc(); 
				});
	ASSERT(ret);

	p->SetPacketOnRecvCallBack(NET_PACKET_HEADBYTE_LSM, this, &LocalSwarm::_OnRecv);

	ResetExternalPort();
	ForceRefresh();

	_DhtQuerySecKeyPrev = _DhtQuerySecKey = os::TickCount::Get();
}

LocalSwarm::~LocalSwarm()
{
	_SafeFree32AL(_pOutputPeers_Front);
	_SafeFree32AL(_pOutputPeers_Back);

	if(_LocalDiscoveryThread.IsRunning())
	{
		_LocalDiscoveryThread.WantExit() = true;
		_LocalDiscoverySocket.Close();
		_LocalDiscoveryThread.WaitForEnding();
	}
}

ULONGLONG LocalSwarm::PacketGet::GetCheckSum() const
{
	return ipp::crc64(((LPCBYTE)this) + sizeof(CheckSum) + sizeof(PacketHeader), GetSize() - sizeof(CheckSum) - sizeof(PacketHeader), 0x8032beef);
}

void LocalSwarm::_LocalDiscoveryFunc()
{
	while(!_LocalDiscoveryThread.WantExit() && !_pNet->bWantStop)
	{
		inet::InetAddr bind;
		bind.SetAsAny();
		
		for(UINT i = DHT_LOCALSWARM_DISCOVERY_PORT_MIN; i<=DHT_LOCALSWARM_DISCOVERY_PORT_MAX; i++)
		{
			bind.SetPort(_LocalDiscoveryPort = i);
			if(_LocalDiscoverySocket.Create(bind, SOCK_DGRAM, 0))
			{
				_LocalDiscoverySocket.EnableDatagramBroadcast();
				VERIFY(_LocalDiscoverySocket.SetBufferSize(32*1024, true));
				VERIFY(_LocalDiscoverySocket.SetBufferSize(32*1024, false));
				_LOGC("[NET]: Local Swarm Discovery bind to "<<bind);

				goto START_IO;
			}
		}

		os::Sleep(4000, &_pNet->bWantStop);
		continue;

START_IO:
		_BroadcastPacketGet();

		BYTE buf[NET_DATAGRAMNETWORK_MTU];

		inet::InetAddr from;
		UINT recved = 0;
		PacketRecvContext ctx;

		while(!_pNet->bWantStop)
			if(_LocalDiscoverySocket.RecvFrom(buf, sizeof(buf), recved, from) && recved)
			{
				if((_LocalDiscoveryPort == from.GetPort() && _pNet->IsLocalIP(*((DWORD*)from.GetBinaryAddress())))
					|| from.IsLoopback()
				)	continue; // drop self-sending
			
				ctx.RecvFrom.IPv4().Set(from);				
				_OnRecv(buf, recved, ctx);
			}
			else if(_LocalDiscoverySocket.IsErrorUnrecoverable(_LocalDiscoverySocket.GetLastError()))
			{
				_LOGC_WARNING("[Net]: LSM Discovery Socket Error="<<_LocalDiscoverySocket.GetLastError()<<", retry binding");
				_LocalDiscoverySocket.Close();
				os::Sleep(100);
				break;
			}
	}
}

void LocalSwarm::InvitePeer(const NetworkAddress& ip) const
{
	_SendPing(ip, false);
}

void LocalSwarm::_LogMsg(const PacketHeader& packet, const NetworkAddress& from)
{
	return;

	switch(packet.Msg)
	{
	case PMID_GET_REPLY:
		_LOG_VERBOSE("LSM-Ack: GET/H="<<((PacketGet&)packet).HostCount<<' '<<tos(from));
		break;
	case PMID_GET:
		_LOG_VERBOSE("LSM-Req: GET/H="<<((PacketGet&)packet).HostCount<<' '<<tos(from));
		break;
	case PMID_PING:
		_LOG_VERBOSE("LSM-Req: PING "<<tos(from));
		break;
	case PMID_PING_REPLY:
		_LOG_VERBOSE("LSM-Ack: PING "<<tos(from));
		break;
	default: 
		_LOG_VERBOSE("LSM-Unk: ["<<packet.Msg<<"] "<<tos(from));
	}
}

void LocalSwarm::_OnRecv(LPCVOID buf, UINT recved, const PacketRecvContext& ctx)
{
	if(ctx.pRelayPeer)return; // relay not allowed

	if(recved > sizeof(PacketHeader))
	{
		auto& packet = *((PacketHeader*)buf);
		if(packet.Version == PacketHeader::VERSION && packet.AppName == _AppName)
		{
#if defined(PLATFORM_DEBUG_BUILD)			
			_LogMsg(packet, ctx.RecvFrom);
#endif			
			switch(packet.Msg)
			{
			case PMID_GET_REPLY:
				if(((PacketGet&)packet).GetSize() <= recved)
				{	EnterCSBlock(_SwarmPeersCS);
					_OnGetReply((PacketGet&)packet);
				}
				break;
			case PMID_GET:
				if(((PacketGet&)packet).GetSize() <= recved)
				{	EnterCSBlock(_SwarmPeersCS);
					_OnGet((PacketGet&)packet, ctx);
				}
				break;
			case PMID_PING:
				if(sizeof(PacketPing) <= recved)
				{	_OnPing((PacketPing&)packet, ctx);
				}
				break;
			case PMID_PING_REPLY:
				if(sizeof(PacketPing) <= recved)
				{
					_OnPingReply((PacketPing&)packet, ctx);
				}
				break;
			case PMID_FINDNODE:
				if(sizeof(PacketDHTQuery) <= recved)
					_OnDhtFindNode((PacketDHTQuery&)packet, ctx);
				break;
			case PMID_GETPEER:
				if(sizeof(PacketDHTQuery) <= recved)
					_OnDhtGetPeer((PacketDHTQuery&)packet, ctx);
				break;
			case PMID_FINDNODE_REPLY:
				{	auto& list = (PacketDhtIPList&)packet;
					if(list.GetSize() <= recved)
						_OnDhtFindNodeReply(list, ctx);
				}
				break;			
			case PMID_GETPEER_REPLY:
				{	auto& list = (PacketDhtIPList&)packet;
					if(list.GetSize() <= recved)
						_OnDhtGetPeerReply(list, ctx);
				}
				break;
			}
		}
	}
}

void LocalSwarm::_OnPing(const PacketPing& packet, const PacketRecvContext& ctx)
{
	PacketPOD<PacketPing> p;
	p->Version = PacketHeader::VERSION;
	p->AppName = _AppName;
	p->Flag = 0;
	p->Msg = PMID_PING_REPLY;
	p->Timestamp = ((PacketPing&)packet).Timestamp;
	p->ObservedByRecipient = ctx.RecvFrom.IPv4();
	p->SenderDHT = _pNet->GetNodeId();
	p->SenderDesc = *_pNodeDesc;
	_pNet->Send(p, ctx.RecvFrom);

	if(packet.Flag & PCKF_REPLY_ADDITIONAL_GET)
	{	
		DWORD local = _pNet->GetLocalIP(p->ObservedByRecipient.IP);

		PacketPOD<PacketGet> p;
		_PreparePacketGet(p, PMID_GET_REPLY, local);
		_pNet->Send(p, ctx.RecvFrom);
	}
	else
	{
		if(_SwarmPeers.Find(ctx.RecvFrom) < 0)
			_SendPing(ctx.RecvFrom, false);
	}
}

void LocalSwarm::_OnPingReply(const PacketPing& packet, const PacketRecvContext& ctx)
{
	LONGLONG cur_time = os::Timestamp::Get();
	if(cur_time < packet.Timestamp)return;

	UINT latency = (UINT)(cur_time - packet.Timestamp);
	auto& h = ctx.RecvFrom.IPv4();

	{	EnterCSBlock(_SwarmPeersCS);

		if(!_pNet->IsSubnetIP(h.IP) && _ExternalIPs.Sample(packet.ObservedByRecipient.IP) == _ExternalIPs.MATCHED_WITH_TOP)
			_ExternalPorts.Sample(packet.ObservedByRecipient.Port());

		int i = (int)_SwarmPeers.Find(ctx.RecvFrom);
		if(i>=0)
		{	_SwarmPeers[i].last_recv = _Tick;
			_SwarmPeers[i].UpdateLatency(latency/NET_TICK_UNIT_FLOAT);
			_SwarmPeers[i].DhtAddress = packet.SenderDHT;
		}
		else
		{	
			auto& nh = _SwarmPeers.push_back();
			nh.NetAddress.IPv4() = h;
			nh.last_recv = _Tick;
			nh.last_sent = _Tick;
			nh.latency_average = latency/NET_TICK_UNIT_FLOAT;
			nh.discover_time = _Tick;
			nh.DhtAddress = packet.SenderDHT;
		    nh.IsExternal = !_pNet->IsSubnetIP(h.IP);
			nh.NodeDesc = packet.SenderDesc;

			_LOGC("Discover Local Swarm Peer: "<<tos(ctx.RecvFrom.IPv4()));
			_HelpDhtBootstrap(&ctx.RecvFrom);

			if(_SwarmPeers.GetSize() == 1)
				CoreEvent(MODULE_NETWORK, NETWORK_CONNECTIVITY_CHANGED);

			CoreEvent(MODULE_NETWORK, NETWORK_LOCAL_SWARM_CHANGED);

			if(nh.IsExternal && _pNet->GetConnectionState() == LNS_UNMAPPED)
			{
				_BroadcastPacketGet(true);
			}

			_bSwarmPeersDirty = true;
		}
	}

	if(packet.SenderDesc.LocalTime32)
		_pNet->SampleNetworkTime(packet.SenderDesc.LocalTime32, latency, ctx);
}

void LocalSwarm::_SendPing(const NetworkAddress& to, bool is_external) const
{
	PacketPOD<PacketPing> p;
	p->Version = PacketHeader::VERSION;
	p->AppName = _AppName;
	p->Flag = is_external?PCKF_REPLY_ADDITIONAL_GET:0;
	p->Msg = PMID_PING;
	p->Timestamp = os::Timestamp::Get();
	p->SenderDHT = _pNet->GetNodeId();
	p->SenderDesc = *_pNodeDesc;
	rt::Zero(p->ObservedByRecipient);

	_pNet->Send(p, to);
}

void LocalSwarm::_OnGetReply(const PacketGet& packet)
{
	ASSERT(packet.IsValid());

	EnterCSBlock(_SwarmPeersCS);
	for(UINT i=0; i<packet.HostCount; i++)
	{
		auto& h = packet.Hosts[i];

		if(_pNet->IsLocalIP(h.IP) && _pNet->GetLocalPort() == h.Port())
			continue;

		if(IsExternalAddressAvailable() && h.IP == _ExternalIPs.Get() && h.Port() == _ExternalPorts.Get())
			continue;

		NetworkAddress a(h);
		if(_SwarmPeers.Find(a) < 0)
			_SendPing(a, false);
	}
}

void LocalSwarm::_PreparePacketGet(PacketGet& packet, UINT msg_type, DWORD local_ip)
{
	packet.Version = PacketHeader::VERSION;
	packet.Flag = 0;
	packet.AppName = _AppName;
	packet.Msg = msg_type;

	if(local_ip)
	{
		packet.HostCount = 1;
		auto& ip = packet.Hosts[0];
		ip.IP = local_ip;
		ip.SetPort(_pNet->GetLocalPort());
	}
	else
	{
		packet.HostCount = 0;

		THREADSAFEMUTABLE_SCOPE(_pNet->GetLocalInterfaces());
		auto& nic = _pNet->GetLocalInterfaces().GetImmutable();
		for(auto it : nic)
		{
			auto& ip = packet.Hosts[packet.HostCount++];
			ip.IP = it.second.LocalIP;
			ip.SetPort(_pNet->GetLocalPort());

			if(packet.HostCount >= PacketGet::MAX_COUNT)
				break;
		}
	}

	UINT i=0;
	{	EnterCSBlock(_SwarmPeersCS);
		if(_SwarmPeers.GetSize())
		{
			for(; i < _SwarmPeers.GetSize(); i++)
			{
				auto& n = _SwarmPeers[(i + __LocalSwarmPeerScanBase)%_SwarmPeers.GetSize()];

				// don't propagate external or dead peers
				// if(n.IsExternal && _pNet->GetConnectionState() != LNS_UNMAPPED)continue;

				packet.Hosts[packet.HostCount] = n.NetAddress.IPv4();
				packet.HostCount++;

				if(packet.HostCount >= PacketGet::MAX_COUNT)
					break;
			}
			__LocalSwarmPeerScanBase = (__LocalSwarmPeerScanBase + i)%_SwarmPeers.GetSize();
		}
	}
	
	packet.CheckSum = packet.GetCheckSum();

}

void LocalSwarm::_OnGet(const PacketGet& packet_in, const PacketRecvContext& ctx)
{
	DWORD local = _pNet->GetLocalIP(ctx.RecvFrom.IPv4().IP);

	PacketGet packet;
	_PreparePacketGet(packet, PMID_GET_REPLY, local);

	inet::InetAddr to;
	ctx.RecvFrom.IPv4().Export(to);
	_LocalDiscoverySocket.SendTo(&packet, packet.GetSize(), to);

	_OnGetReply(packet_in);
}

void LocalSwarm::SetBroadcastAddresses(const DWORD* cast_addr, UINT co)
{
	ASSERT(co <= NET_LOCAL_ADDRESS_MAXCOUNT);

	if(co < _BroadcastAddressCount)
		_BroadcastAddressCount = co;

	memcpy(_BroadcastAddresses, cast_addr, sizeof(DWORD)*co);
	_BroadcastAddressCount = co;
}

void LocalSwarm::_BroadcastPacketGet(bool as_reply)
{
	inet::InetAddr to;

	PacketGet packet;
	_PreparePacketGet(packet, as_reply?PMID_GET_REPLY:PMID_GET);

	for(UINT a=0; a<_BroadcastAddressCount; a++)
	{
		for(UINT i=DHT_LOCALSWARM_DISCOVERY_PORT_MIN; i<=DHT_LOCALSWARM_DISCOVERY_PORT_MAX; i++)
		{
			to.SetBinaryAddress(&_BroadcastAddresses[a]);
			to.SetPort(i);
			_LocalDiscoverySocket.SendTo(&packet, sizeof(PacketGet), to);
		}
	}
}

void LocalSwarm::OnTick(UINT tick)
{
	_Tick = tick;

	if((tick%20) == 0)
	{
		_DhtQuerySecKeyPrev = _DhtQuerySecKey;
		_DhtQuerySecKey = rt::Randomizer(_DhtQuerySecKey).GetNext()*(tick+1);
	}

	if((tick%30) == 10)
		_HelpDhtBootstrap();

	{	EnterCSBlock(_SwarmPeersCS);
		_ActiveSubnetSwarmPeersCount = 0;
		_HasActiveExternalPeer = false;

		UINT open = 0;
		for(UINT i=0; i<_SwarmPeers.GetSize(); i++)
		{
			auto& p = _SwarmPeers[i];

			if(p.last_sent > p.last_recv)
			{
				if(p.IsGone(_Tick))
				{
					_bSwarmPeersDirty = true;
					continue; // peer is gone
				}

				if(p.IsNearlyGone(_Tick))
					_SendPing(p.NetAddress, p.IsExternal);
			}
			else if((tick - p.last_recv) > (UINT)rt::max((int)DHT_LOCALSWARM_PING_INTERVAL, (int)(9*(((int)DHT_LOCALSWARM_ZOMBIE_BY_LASTRECV_TIMEOUT) - p.latency_average*2)/10 + 0.5)))
			{	_SendPing(p.NetAddress, p.IsExternal);
				p.last_sent = tick;
			}

			if(p.IsExternal)
				_HasActiveExternalPeer = true;
			else
				_ActiveSubnetSwarmPeersCount++;

			if(i != open)_SwarmPeers[open] = p;

			open++;
		}

		if(_SwarmPeers.GetSize() != open)
		{
			_SwarmPeers.ShrinkSize(open);
			CoreEvent(MODULE_NETWORK, NETWORK_LOCAL_SWARM_CHANGED);

			if(open == 0)
				CoreEvent(MODULE_NETWORK, NETWORK_CONNECTIVITY_CHANGED);
		}

		if(_bSwarmPeersDirty)
		{
			_bSwarmPeersDirty = false;

			_pOutputPeers_Back->Count = 0;
			if(_SwarmPeers.GetSize() > _pOutputPeers_Back->Reserved)
			{
				auto* new_list = (LocalPeerList*)_Malloc32AL(BYTE, offsetof(LocalPeerList, Peers) + sizeof(NetworkAddress)*_SwarmPeers.GetSize());
				new_list->Reserved = (UINT)_SwarmPeers.GetSize();
				new_list->Count = 0;
				rt::Swap(new_list, _pOutputPeers_Back);
				_SafeFree32AL_Delayed(new_list, 2000);
			}

			ASSERT(_pOutputPeers_Back->Reserved >= _SwarmPeers.GetSize());
			for(UINT i=0; i<_SwarmPeers.GetSize(); i++)
				_pOutputPeers_Back->Peers[i] = _SwarmPeers[i].NetAddress;

			_pOutputPeers_Back->Count = (UINT)_SwarmPeers.GetSize();

			rt::Swap(_pOutputPeers_Back, _pOutputPeers_Front);
		}
	}

	if(_fd_DHT_LOCALSWARM_BROADCAST_DISCOVERY(tick))
	{
		_fd_DHT_LOCALSWARM_BROADCAST_DISCOVERY
			.SetInterval((_ActiveSubnetSwarmPeersCount+1)*DHT_LOCALSWARM_BROADCAST_DISCOVERY_INTERVAL);

		_BroadcastPacketGet();
	}

	if(	_pNet->GetConnectionState() == NCS_PRIVATE_INTRANET &&
		//!(_HasActiveExternalPeer && _pNet->GetConnectionState() == LNS_LOCALSWARM_EXTERNAL_IP) &&
		!_HasActiveExternalPeer &&
		_pNet->GetNatMappedAddress().IP != 0 &&
		_fd_DHT_LOCALSWARM_EXTERNAL_DISCOVERY(tick)
	)
	{	// discovery nodes in external side of the router by sending get packet to random IP of external network
		DWORD ip_probe;
		rt::SwitchByteOrderTo(_pNet->GetNatMappedAddress().IP, ip_probe);

		UINT co = rt::max(1U, DHT_LOCALSWARM_EXTERNAL_DISCOVERY_BATCHSIZE/(1+_ActiveSubnetSwarmPeersCount));
		signed char rng[DHT_LOCALSWARM_EXTERNAL_DISCOVERY_BATCHSIZE];

		rt::Randomizer((UINT)time(nullptr)).Randomize(rng, DHT_LOCALSWARM_EXTERNAL_DISCOVERY_BATCHSIZE);

		NetworkAddress to;
		to.IPv4().SetPort(DHT_LOCALSWARM_DISCOVERY_PORT_MIN);

		PacketPOD<PacketGet> p;
		p->Version = PacketHeader::VERSION;
		p->AppName = _AppName;
		p->Flag = PCKF_REPLY_ADDITIONAL_GET;
		p->Msg = PMID_GET;
		p->HostCount = 0;
		p->CheckSum = p->GetCheckSum();

		for(UINT i = 0; i<co; i++)
		{
			DWORD ip;
			rt::SwitchByteOrderTo(ip_probe + (int)rng[i], ip);  // random an IP

			for(UINT a=0; a<3; a++)
			{	to.IPv4().Set(&ip, DHT_LOCALSWARM_DISCOVERY_PORT_MIN + a);
				_pNet->Send(p, to);
			}

			//_LOGC_VERBOSE("Random Ping External IP: "<<tos(to).TrimAfter(':'));
		}
	}
}

void LocalSwarm::ResetExternalPort()
{
	_ExternalPorts.ClampWeight(1);
	_ExternalIPs.ClampWeight(1);
}

void LocalSwarm::ForceRefresh()
{
	EnterCSBlock(_SwarmPeersCS);
	_SwarmPeers.SetSize(0);
	_HasActiveExternalPeer = false;
	_ActiveSubnetSwarmPeersCount = 0;
	__LocalSwarmPeerScanBase = 0;

	_fd_DHT_LOCALSWARM_EXTERNAL_DISCOVERY.Reset();
	_fd_DHT_LOCALSWARM_BROADCAST_DISCOVERY.Reset();

	_BroadcastPacketGet();
}

void LocalSwarm::Awaken()
{
    _BroadcastPacketGet();
}

void LocalSwarm::_OnDhtFindNodeReply(const PacketDhtIPList& packet, const PacketRecvContext& ctx)
{
	if(!_CheckDhtQuerySecKey(packet.SecureKey))return;
		
	if(_pNet && _pNet->HasDHT() && !_pNet->DHT().IsMature())
	{
		for(UINT i=0; i<packet.Count; i++)
		{
			_pNet->DHT().SendBootstrapPing(ctx.RecvFrom);
		}
	}
}

void LocalSwarm::_OnDhtFindNode(const PacketDHTQuery& packet, const PacketRecvContext& ctx)
{
	if(_pNet && _pNet->HasDHT())
	{
		PacketBuf<> buf;
		auto& reply = *(PacketDhtIPList*)buf.Claim(0);

		DhtSpace::_CollectedNode  nodes[8];
		reply.Count = _pNet->DHT().GetClosestNodes(packet.Target, nodes, 8);
		if(reply.Count)
		{
			reply.SecureKey = packet.SecureKey;
			for(UINT i=0; i<reply.Count; i++)
				reply.Nodes[i] = nodes[i].node.NetAddress;

			reply.Msg = PMID_FINDNODE_REPLY;
			reply.Flag = 0;
			reply.Version = PacketHeader::VERSION;
			reply.AppName = _AppName;

			buf.Commit(reply.GetSize());

			_pNet->Send(buf, ctx.RecvFrom, PSF_DROPABLE);
		}
	}
}

void LocalSwarm::_HelpDhtBootstrap(const NetworkAddress* to) const
{
	if(_pNet && _pNet->HasDHT())
	{
		auto& dht = _pNet->DHT();
		if(dht.IsMature())return;

		PacketBuf<> buf;
		auto& query = buf.AppendPOD<PacketDHTQuery>();
		query.Target = dht.GetNodeId();
		query.SecureKey = _DhtQuerySecKey;

		query.Msg = PMID_FINDNODE;
		query.Flag = 0;
		query.Version = PacketHeader::VERSION;
		query.AppName = _AppName;

		if(to)
		{
			_pNet->Send(buf, *to, PSF_DROPABLE);
		}
		else
		{
			EnterCSBlock(_SwarmPeersCS);
			if(_pOutputPeers_Front && _pOutputPeers_Front->Count)
			{
				for(UINT i=0; i<_pOutputPeers_Front->Count; i++)
					_pNet->Send(buf, _pOutputPeers_Front->Peers[i], PSF_DROPABLE);
			}
		}
	}
}

void LocalSwarm::_OnDhtGetPeerReply(const PacketDhtIPList& packet, const PacketRecvContext& ctx)
{

}

void LocalSwarm::_OnDhtGetPeer(const PacketDHTQuery& packet, const PacketRecvContext& ctx)
{
}

bool LocalSwarm::IsExternalAddressAvailable() const
{
	return _ExternalIPs.GetWeight() > 0 && _ExternalPorts.GetWeight() > 0;
}

IPv4 LocalSwarm::GetExternalAddress() const
{
	ASSERT(!_ExternalIPs.IsEmpty() && !_ExternalPorts.IsEmpty());

	IPv4 ret;
	ret.Set(&_ExternalIPs.Get(), _ExternalPorts.Get());
	return ret;
}

UINT LocalSwarm::GetExternalPort() const
{
	ASSERT(!_ExternalIPs.IsEmpty() && !_ExternalPorts.IsEmpty());
	return _ExternalPorts.Get();
}

void LocalSwarm::GetStateReport(rt::String& out)
{
    static const char LN = '\n';

	out +=	rt::SS("*** Local Swarm Discovery ***") + LN;
			
	if(_BroadcastAddressCount)
	{
		out += rt::SS("Broadcast=");
		for(UINT i=0; i<_BroadcastAddressCount; i++)
		{
			if(i)out += ',';
			out += tos(_BroadcastAddresses[i]);
		}
	}
	
	out += rt::SS(" Discovery");
	
	if(_LocalDiscoverySocket.IsValid())
		out += rt::SS(":") + _LocalDiscoveryPort;
	else
		out += rt::SS(":off");
	
	EnterCSBlock(_SwarmPeersCS);
	if(!_ExternalIPs.IsEmpty())
	{
		out += LN + rt::SS("External IP:");
		for(UINT i=0; i<_ExternalIPs.GetSize(); i++)
		{
			if(_ExternalIPs.GetWeight(i) > 0)
			{
				DWORD ip = _ExternalIPs.Get(i);
				out += rt::SS(" ") + tos(ip) + '/' + _ExternalIPs.GetWeight(i);
			}
		}

		out += LN + rt::SS("External Port:");
		for(UINT i=0; i<_ExternalPorts.GetSize(); i++)
		{
			if(_ExternalPorts.GetWeight(i) > 0)
			{
				out += rt::SS(" ") + _ExternalPorts.Get(i) + '/' + _ExternalIPs.GetWeight(i);
			}
		}
	}

	out += LN + rt::SS("Swarm Size: ") + _ActiveSubnetSwarmPeersCount + '/' + (UINT)_SwarmPeers.GetSize() + LN;
	for(UINT i=0; i<_SwarmPeers.GetSize(); i++)
	{
		auto& p = _SwarmPeers[i];
		out +=	rt::SS("  - <") + tos(p.DhtAddress).SubStr(0, 16) + "> [" + p.NodeDesc.GetNodeName() + ']' + ' ' +
				(p.IsExternal?"External":"Internal") + ' ' + 
				tos(p.NetAddress) + " LTNC:" + (int)(p.latency_average*NET_TICK_UNIT_FLOAT + 0.5f) + LN;
	}
}

void LocalSwarm::GetState(NetworkState_LSM& ns)
{
	EnterCSBlock(_SwarmPeersCS);

	ns.LSM_PeerCount = (UINT)_SwarmPeers.GetSize();
	ns.LSM_SubnetPeerCount = _ActiveSubnetSwarmPeersCount;
	
	if(_SwarmPeers.GetSize())
	{	
		double tot = 0;
		float max_v = 0;
		for(UINT i=0; i<_SwarmPeers.GetSize(); i++)
		{
			auto& p = _SwarmPeers[i];
			tot += p.latency_average;
			max_v = rt::max(max_v, p.latency_average);
		}

		ns.LSM_Latency = (UINT)((tot/_SwarmPeers.GetSize())*NET_TICK_UNIT + 0.5f);
		ns.LSM_LatencyMax = (UINT)((max_v)*NET_TICK_UNIT + 0.5f);
	}
	else
	{	ns.LSM_Latency = ns.LSM_LatencyMax = 0;
	}
}

} // namespace upw
