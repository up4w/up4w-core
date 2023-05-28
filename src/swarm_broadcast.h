#pragma once
#include "netsvc_types.h"
#include "../src/dht/dht_base.h"

namespace upw
{

class NetworkServiceCore;

static const UINT SWARM_ID_INVALID = 0;

class SwarmBroadcast // Low level swarm communication, data size < MTU
{
protected:
	NetworkServiceCore*	_pCore;

protected:
	typedef rt::hash_map<DhtAddress, UINT>	t_SwarmAddress2Id;
	// Swarm Mapping
	struct SwarmSlot
	{
		DhtAddress				Addr;
		bool					bPrivate;
		DhtAddress				PrivateSecret; // if bPrivate
		mutable volatile int	InUse;

		SwarmSlot(){ rt::Zero(*this); }
		bool			IsTaken() const { return InUse > 0; }
		void			AddUsageCount() const { os::AtomicIncrement(&InUse); }
		void			Release() const { ASSERT(IsTaken()); os::AtomicDecrement(&InUse); }
	};
	struct SwarmIdMap
	{
		rt::BufferEx<SwarmSlot>	Id2Address;
		t_SwarmAddress2Id		Address2Id;
		SwarmSlot&				GetAddressSlot(UINT swarm_id);
	};
	os::ThreadSafeMutable<SwarmIdMap>	_SwarmIdMap;
	typedef os::_details::_TSM_Updater<os::ThreadSafeMutable<SwarmIdMap>> t_SwarmIdMapUpdater;

	void	_OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx);
	UINT	_JoinExisting(const SwarmIdMap& map, const DhtAddress& target, const DhtAddress* private_secret) const;
	UINT	_Join(const DhtAddress& target, const DhtAddress* private_secret, UINT swarm_size, const rt::String_Ref& boot_file, const DhtAddress* alt_node_id = nullptr);

	auto	_OnSwarmJoinedWithoutDHT(t_SwarmIdMapUpdater& new_map, UINT* swarm_id, const DhtAddress& target, bool is_private) -> SwarmSlot*;

public:
	SwarmBroadcast(NetworkServiceCore* p);

	UINT	Join(const DhtAddress& target, UINT swarm_size, const rt::String_Ref& boot_file = nullptr);  // return swarm_id (SWARM_ID_INVALID if failed)
	UINT	JoinPrivate(const DhtAddress& target, const DhtAddress& private_secret, UINT swarm_size = 8, const DhtAddress* alt_node_id = nullptr);
	void	Leave(UINT swarm_id);

	int		Broadcast(Packet& packet, UINT swarm_id, const NetworkAddress* skip = nullptr, PACKET_SENDING_FLAG flag = PSF_NORMAL);

	UINT	GetActiveDegree(UINT swarm_id);	// count DHT peers only
	UINT	GetSwarmIdFromAddress(const DhtAddress& addr) const;
	auto	GetAddressFromSwarmId(UINT swarm_id) const -> const DhtAddress*;		// don't hold the pointer for future use
	UINT	GetDefaultSwarmId() const;
	void	GetSwarmAddresses(rt::BufferEx<DhtAddress>& out) const;
};

} // namespace upw
