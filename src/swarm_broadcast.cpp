#include "swarm_broadcast.h"
#include "local_swarm.h"
#include "./dht/dht.h"
#include "netsvc_core.h"
#include "../externs/miniposix/core/ext/ipp/ipp_core.h"


namespace upw
{

SwarmBroadcast::SwarmBroadcast(NetworkServiceCore* p)
	:_pCore(p)
{
	p->SetPacketOnRecvCallBack(NET_PACKET_HEADBYTE_LSM_BROADCAST, this, &SwarmBroadcast::_OnRecv);
}

void SwarmBroadcast::_OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx)
{
	if(len < sizeof(DhtAddress) + 2)
		return;

	auto& addr = *(DhtAddress*)(((LPCBYTE)pData)+1);

	THREADSAFEMUTABLE_SCOPE(_SwarmIdMap);
	auto& map = _SwarmIdMap.GetImmutable().Address2Id;

	if(map.find(addr) != map.end())
		_pCore->OnRecv(((LPCBYTE)pData) + 1 + sizeof(DhtAddress), len - 1 - sizeof(DhtAddress), rt::_CastToNonconst(ctx));
}

UINT SwarmBroadcast::GetActiveDegree(UINT swarm_id)
{
	UINT ret = 0;

	if(_pCore->HasDHT())
		ret += _pCore->DHT().GetSwarmPeers(swarm_id).ForwardCount;

	if(_pCore->HasLSM())
		ret += _pCore->LSM().GetPeerCount();

	return ret;
}

SwarmBroadcast::SwarmSlot& SwarmBroadcast::SwarmIdMap::GetAddressSlot(UINT swarm_id)
{
	ASSERT(swarm_id <= DHT_TRANSCATION_ID_MAX);

	if(Id2Address.GetSize() <= swarm_id)
		VERIFY(Id2Address.ChangeSize(swarm_id+1));

	return Id2Address[swarm_id];
}

UINT SwarmBroadcast::_JoinExisting(const SwarmIdMap& map, const DhtAddress& target, const DhtAddress* private_secret) const
{
	auto it = map.Address2Id.find(target);
	if(it != map.Address2Id.end())
	{
		auto& slot = map.Id2Address[it->second];
		if(	(!slot.bPrivate) ||
			(slot.bPrivate && private_secret && *private_secret == slot.PrivateSecret)
		)
		{	slot.AddUsageCount();
			return it->second;
		}
	}

	return SWARM_ID_INVALID;
}

UINT SwarmBroadcast::Join(const DhtAddress& target, UINT swarm_size, const rt::String_Ref& boot_file)
{
	return _Join(target, nullptr, swarm_size, boot_file);
}

UINT SwarmBroadcast::JoinPrivate(const DhtAddress& target, const DhtAddress& private_secret, UINT swarm_size, const DhtAddress* alt_node_id)
{
	return _Join(target, &private_secret, swarm_size, nullptr, alt_node_id);
}

UINT SwarmBroadcast::_Join(const DhtAddress& target, const DhtAddress* private_secret, UINT swarm_size, const rt::String_Ref& boot_file, const DhtAddress* alt_node_id)
{
	ASSERT(NET_BROADCAST_DEGREE_MAX >= swarm_size);
	
	UINT sid = SWARM_ID_INVALID;

	{	// looking for existing swarm
		THREADSAFEMUTABLE_SCOPE(_SwarmIdMap)
		sid = _JoinExisting(_SwarmIdMap.GetImmutable(), target, private_secret);
	}

	if(sid != SWARM_ID_INVALID)return sid;

	{	// create new swarm
		THREADSAFEMUTABLE_UPDATE(_SwarmIdMap, new_map);
		sid = _JoinExisting(new_map.Get(), target, private_secret);
		if(sid != SWARM_ID_INVALID)return sid;

		if(_pCore->HasDHT())
		{
			 sid = private_secret?_pCore->DHT().StartJoinPrivateSwarm(target, *private_secret, swarm_size, alt_node_id)
								 :_pCore->DHT().StartJoinSwarm(target, swarm_size, boot_file);

			if(sid != SWARM_ID_INVALID)
			{
				 new_map->Address2Id.insert(std::make_pair(target, sid));

				 auto& slot = new_map->GetAddressSlot(sid);
				 ASSERT(slot.InUse == 0);
				 slot.AddUsageCount();
				 slot.Addr = target;
				 slot.bPrivate = private_secret;
				 if(private_secret)slot.PrivateSecret = *private_secret;

				 return sid;
			}
		}
		else
		{
			new_map->Id2Address.ExpandSize(2); // [0] is a dummy entry for SWARM_ID_INVALID
			sid = (UINT)new_map->Id2Address.GetSize();

			for(UINT i=1; i<new_map->Id2Address.GetSize(); i++)
				if(!new_map->Id2Address[i].IsTaken())
				{	sid = i;
					break;
				}

			auto& slot = new_map->GetAddressSlot(sid);
			ASSERT(!slot.IsTaken());
			slot.AddUsageCount();
			slot.Addr = target;

			new_map->Address2Id.insert(std::make_pair(target, sid));

			slot.bPrivate = private_secret;
			if(private_secret)slot.PrivateSecret = *private_secret;

			return sid;
		}
	}

	return SWARM_ID_INVALID;
}

UINT SwarmBroadcast::GetSwarmIdFromAddress(const DhtAddress& addr) const
{
	THREADSAFEMUTABLE_SCOPE(_SwarmIdMap)
	auto& map = _SwarmIdMap.GetImmutable().Address2Id;
	auto it = map.find(addr);
	if(it != map.end())
		return it->second;

	return SWARM_ID_INVALID;
}

void SwarmBroadcast::GetSwarmAddresses(rt::BufferEx<DhtAddress>& out) const
{
	out.ShrinkSize(0);

	THREADSAFEMUTABLE_SCOPE(_SwarmIdMap)
	for(auto& slot: _SwarmIdMap.GetImmutable().Id2Address)
	{
		if(slot.IsTaken())
			out.push_back(slot.Addr);
	}
}

const DhtAddress* SwarmBroadcast::GetAddressFromSwarmId(UINT swarm_id) const
{
	THREADSAFEMUTABLE_SCOPE(_SwarmIdMap)
	auto& slots = _SwarmIdMap.GetImmutable().Id2Address;
	if(slots.GetSize() > swarm_id && slots[swarm_id].IsTaken())
		return &slots[swarm_id].Addr;

	return nullptr;
}

UINT SwarmBroadcast::GetDefaultSwarmId() const
{
	THREADSAFEMUTABLE_SCOPE(_SwarmIdMap)
	auto& slots = _SwarmIdMap.GetImmutable().Id2Address;
	for(UINT i=0; i<slots.GetSize(); i++)
		if(slots[i].IsTaken())
			return i;

	return SWARM_ID_INVALID;
}

void SwarmBroadcast::Leave(UINT swarm_id)
{
	{	THREADSAFEMUTABLE_SCOPE(_SwarmIdMap)
		auto& map = _SwarmIdMap.GetImmutable();
		if(map.Id2Address.GetSize() <= swarm_id || !map.Id2Address[swarm_id].IsTaken())
			return;

		auto& slot = map.Id2Address[swarm_id];
		slot.Release();
		if(slot.IsTaken())
			return;
	}

	THREADSAFEMUTABLE_UPDATE(_SwarmIdMap, new_map);
	if(new_map->Id2Address.GetSize() <= swarm_id || !new_map->Id2Address[swarm_id].IsTaken())
		return;

	new_map->Id2Address[swarm_id].InUse = 0;
	new_map->Address2Id.erase(new_map->Id2Address[swarm_id].Addr);

	if(_pCore->HasDHT())
		_pCore->DHT().StopJoinSwarm(swarm_id);
}

int SwarmBroadcast::Broadcast(Packet& packet, UINT swarm_id, const NetworkAddress* skip, PACKET_SENDING_FLAG flag)
{
	if(_pCore->IsDataServiceSuspended())return 0;

	int sent = 0;

	if(_pCore->HasDHT())
	{
		auto* swarm = _pCore->DHT().GetSwarm(swarm_id);
		if(!swarm) return 0;
		auto& peerlist = swarm->GetPeers();
		const NetworkAddress* peers = nullptr;

		UINT co;
#if defined(NET_BROADCAST_ALLPEERS)
#pragma message("SwarmBroadcast : all peers")
#else
#pragma message("SwarmBroadcast : forward only")
		if(flag&PSF_FORWARD_ONLY)
		{
			peers = peerlist.ForwardPeers();
			if(swarm->GetDegree()/2 > peerlist.ForwardCount)
			{
				UINT borrow = rt::min(peerlist.BackwardCount, swarm->GetDegree()/2 - peerlist.ForwardCount);
				peers -= borrow;
				co = peerlist.ForwardCount + borrow;
			}
			else
				co = peerlist.ForwardCount;
		}
		else
#endif // #if defined(NET_BROADCAST_ALLPEERS)
		{
			peers = peerlist.BackwardPeers();
			co = peerlist.TotalCount();
		}

		for(UINT i=0; i<co; i++)
		{
			if(skip && *skip == peers[i])continue;
			if(_pCore->Send(packet, peers[i], flag))
				sent++;
		}
	}

	if(_pCore->HasLSM() && (PSF_SKIP_LOCALSWARM&flag) == 0)
	{
		auto& peers = _pCore->LSM().GetPeers();
		if(peers.Count)
		{
			THREADSAFEMUTABLE_SCOPE(_SwarmIdMap);
			auto& idadd = _SwarmIdMap.GetImmutable().Id2Address;
			if(idadd.GetSize() <= swarm_id || !idadd[swarm_id].IsTaken())return sent;

			static const char HEADER = NET_PACKET_HEADBYTE_LSM_BROADCAST;
			packet.PrependWithPOD(idadd[swarm_id].Addr);
			packet.PrependWithPOD(HEADER);

			for(UINT i=0; i<peers.Count; i++)
			{
				if(skip && *skip == peers.Peers[i])continue;
				if(_pCore->Send(packet, peers.Peers[i], flag))
					sent++;
			}

			packet.PrependReset();
		}
	}

	return sent;
}

} // namespace upw
