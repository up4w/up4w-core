#pragma once

#include "../../externs/miniposix/essentials.h"

//#define OXD_DUMP_DHT_MESSAGE
//#define OXD_NET_DEBUG_REPORT

#define DHT_MAIN_ROUTING_BOOTSTRAP_LIST		"bootstrap.nodes"
#define DHT_SWARM_BOOTSTRAP_EXTNAME			".nodes"
#define DHT_CONNSWARM_BOOTSTRAP_EXTNAME		"conn.nodes"

namespace upw
{

static const DWORD	DHT_VERSION_DEFAULT								= 0x30305455;	// UT00
static const DWORD	DHT_APP_TAG_DEFAULT								= 0x30544844;	// DHT0
static const UINT	DHT_ADDRESS_SIZE								= 20;  // MUST multiple of 4
static const UINT	DHT_DISTANCE_MAX								= DHT_ADDRESS_SIZE*8;

static const UINT	DHT_BUCKET_SIZE									= 8;
static const UINT	DHT_BUCKET_DISTANCE_BASE						= DHT_DISTANCE_MAX*3/4;
static const UINT	DHT_SPACE_SIZE									= DHT_ADDRESS_SIZE*8+1;

static const UINT	DHT_LOCALSWARM_DISCOVERY_PORT_MIN				= 8032;
static const UINT	DHT_LOCALSWARM_DISCOVERY_PORT_MAX				= 8040;
static const UINT	DHT_LOCALSWARM_PING_INTERVAL					= 150;	// in Tick Unit
static const UINT	DHT_LOCALSWARM_ZOMBIE_BY_LASTRECV_TIMEOUT		= 100; // in msec
static const UINT	DHT_LOCALSWARM_NODE_GONE_LATENCY_MULTIPLIER		= 50;
static const UINT	DHT_LOCALSWARM_BROADCAST_DISCOVERY_INTERVAL		= 300;	// in Tick Unit
static const UINT	DHT_LOCALSWARM_EXTERNAL_DISCOVERY_INTERVAL		= 100;	// in Tick Unit
static const UINT	DHT_LOCALSWARM_EXTERNAL_DISCOVERY_BATCHSIZE		= 64;

static const UINT	DHT_NODE_EXTERNAL_IP_MATURE						= 3;
static const UINT	DHT_NODE_DISCOVER_QUEUE_SIZE					= 100*1024;
static const UINT	DHT_NODE_INTRODUCE_QUEUE_SIZE					= DHT_NODE_DISCOVER_QUEUE_SIZE*20;
static const UINT	DHT_MESSAGE_TRANSCATIONID_MAXLEN				= 256;
static const UINT	DHT_MESSAGE_TOKEN_MAXLEN						= 256;
static const UINT	DHT_MESSAGE_PEERINFO_MAXCOUNT					= 128;

static const UINT	DHT_KNOWN_NODES6_SIZE_LIMIT						= 1024;
static const UINT	DHT_VERIFIED_NODES6_SIZE_LIMIT					= 128;
static const UINT   DHT_NODES6_NUM_FINDSELF_PER_UPDATE				= 4;


// With tick unit = 100, an instance can continuously run 12.9 years, which is 4G/( (1000*3600*24*365)/NET_TICK_UNIT )
static const UINT	DHT_TOKEN_UPDATE_INTERVAL						= 100;  // in Tick Unit
static const UINT	DHT_BOOTSTRAP_INTERVAL							= 300;  // in Tick Unit
static const UINT	DHT_BOOTSTRAP_BOOST_INTERVAL					= 20;  // in Tick Unit
static const UINT	DHT_BOOTSTRAP_UPDATE_INTERVAL					= 10*60*10;  // in Tick Unit
static const UINT	DHT_BOOTSTRAP_NODES_MAX							= 256;
static const UINT	DHT_BOOTSTRAP_BOOST_COUNT						= 10;
static const UINT	DHT_LATENCY_SMOOTHING_FACTOR					= 7;
																		    
static const UINT	DHT_SPACE_UPDATE_INTERVAL_MAX					= 1000;  // in Tick Unit
static const UINT	DHT_SPACE_UPDATE_INTERVAL_MIN					= 100;   // in Tick Unit
static const UINT	DHT_SPACE_NODE_REMOVE_BY_LASTRECV_TIMEOUT		= 12000; // in Tick Unit
static const UINT	DHT_SPACE_NODE_ZOMBIE_BY_LASTRECV_TIMEOUT		= 6000;  // in Tick Unit, also affects Transcation/Swarm
static const UINT	DHT_SPACE_NODE_PING_BY_LASTRECV_TIMEOUT			= 3000;  // in Tick Unit
static const UINT	DHT_SPACE_NODE_SHORTAGE							= DHT_BUCKET_SIZE*7/10;
static const UINT	DHT_SPACE_DISCOVER_QUEUE_MAXSIZE				= 10240;
static const UINT	DHT_SPACE_NODE_ACCEPTABLE_LATENCY				= 1000; // msec
static const UINT	DHT_SPACE_NODE_GOOD_LATENCY						= 100;  // msec
static const UINT	DHT_SPACE_NODE_HIGH_LATENCY_MULTIPLIER			= 8;
static const UINT	DHT_SPACE_NODE_GOOD_LATENCY_MULTIPLIER			= 2;
static const UINT	DHT_SPACE_EXPECTED_BUCKETS						= 10;	// top 10 buckets should be filled by nodes
static const UINT	DHT_SPACE_EXPECTED_ACTIVE_NODES					= DHT_BUCKET_SIZE*DHT_SPACE_EXPECTED_BUCKETS/2;

static const UINT	DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE			= 8;
static const UINT	DHT_TRANSCATION_GETPEER_ADDITIONAL_INTERVAL		= 600;

static const UINT	DHT_TRANSCATION_ITERATE_INTERVAL				= 10; // in Tick Unit

static const UINT	DHT_TRANSCATION_PING_INTERVAL					= 10; // in Tick Unit, apply to all nodes
static const UINT	DHT_TRANSCATION_NODE_REMOVE_BY_LASTRECV_TIMEOUT	= 300; // in Tick Unit, apply to non-zero distance found nodes
static const UINT	DHT_TRANSCATION_NODE_GONE_LATENCY_MULTIPLIER	= 10;  // multiple of node's average latency
static const UINT	DHT_TRANSCATION_ID_MAX							= 0xfffffe;

static const UINT	DHT_SWARM_BOOTSTRAP_INTERVAL					= 3000;		// in Tick Unit
static const UINT	DHT_SWARM_BOOTSTRAP_BOOST_INTERVAL				= 300;		// in Tick Unit
static const UINT	DHT_SWARM_BOOTSTRAP_BOOST_COUNT					= 5;
static const UINT	DHT_SWARM_BOOTSTRAP_SAVE_INTERVAL				= 300;		// in Tick Unit
static const UINT	DHT_SWARM_BOOTSTRAP_TIMEOUT						= 10000;	// 10 s
static const UINT	DHT_SWARM_USE_STOCK_BOOTSTRAP_AFTER				= 3000;		// 3 s
static const UINT	DHT_SWARM_STABLE_AGE							= 300;		// 30s, in tick
static const UINT	DHT_SWARM_HOSTS_FORGET_INTERVAL					= 15*1000LL;// 15s
static const UINT	DHT_SWARM_ANNOUNCE_REFRESH_INTERVAL				= 12*60*1000LL;	// in msec
static const UINT	DHT_SWARM_ANNOUNCE_REFRESH_PERIOD				= 30*1000LL;	// in msec
static const UINT	DHT_CONNSWARM_ANNOUNCE_REFRESH_INTERVAL			= 6*60*1000LL;	// in msec
static const UINT	DHT_CONNSWARM_ANNOUNCE_REFRESH_PERIOD			= 30*1000LL;	// in msec
static const UINT	DHT_SWARM_ANNOUNCE_FANOUT_SIZE					= 8;
static const UINT	DHT_SWARM_REPLY_PEERLIST_MAX					= 42;
static const UINT	DHT_SWARM_REPLY_PEERLIST_MAX_V6					= 16;
static const UINT	DHT_SWARM_PING_INTERVAL							= 100;	// in Tick Unit
static const UINT	DHT_SWARM_BOOTSTRAP_MAXCOUNT					= 256;	// in Tick Unit
static const UINT	DHT_SWARM_TOKEN_LENGTH_MAX						= 64;
static const UINT	DHT_SWARM_DISCOVERY_HOSTS_MAX					= 600;	// multiple of expected num
static const UINT	DHT_SWARM_ANNOUNCE_HOSTS_MAX					= 400;	// multiple of expected num
static const UINT	DHT_CONNSWARM_DISCOVERY_HOSTS_MAX				= 700;	// multiple of expected num
static const UINT	DHT_CONNSWARM_ANNOUNCE_HOSTS_MAX				= 500;	// multiple of expected num

extern const UINT DHT_SWARM_QUERY_TRANSID_LENGTH;

#pragma pack(push,1)
struct DhtAddress
{
	BYTE	addr[DHT_ADDRESS_SIZE];
	bool	operator <(const DhtAddress& x) const	{ return memcmp(addr, x.addr, DHT_ADDRESS_SIZE) < 0; }
	bool	operator == (const DhtAddress& x) const { return rt::IsEqual(x, *this); }
	bool	operator != (const DhtAddress& x) const { return !rt::IsEqual(x, *this); }
	bool	IsZero() const { return rt::IsZero(*this); }
	bool	FromString(const rt::String_Ref& s);
	void	FromHash(LPCVOID p, UINT sz);
	void	Random();

	static UINT		Match(const DhtAddress& a, const DhtAddress& b);
	static UINT		Distance(const DhtAddress& a, const DhtAddress& b){ return DHT_DISTANCE_MAX - Match(a,b); }
	static bool		CyclicLessThan(const DhtAddress& a, const DhtAddress& b)
					{	auto* x = (ULONGLONG*)&a;		auto* y = (ULONGLONG*)&b;
						if(x[0] != y[0])return rt::CyclicLessThan(x[0], y[0]);
						if(x[1] != y[1])return rt::CyclicLessThan(x[1], y[1]);
						return rt::CyclicLessThan(*(UINT*)&x[2], *(UINT*)&y[2]);		
					}
	static auto&	ZeroValue()
					{	static const rt::_details::Zeros<sizeof(DhtAddress)> _;
						return (const DhtAddress&)_;
					}
};

#pragma pack(pop)

class MainlineDHT;

} // namespace upw

namespace std
{
template<>
struct hash<::upw::DhtAddress>: public rt::_details::hash_compare_fix<::upw::DhtAddress> {};
} // namespace std
