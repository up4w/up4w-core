#pragma once

#define NET_DATAGRAMNETWORK_MTU				1499*3
#define NET_PACKET_SIZEMAX					1280
#define NET_PACKET_PREFIX_DEFAULT_SIZE		32
#define	NET_NAT_PASSTHROUGH_TIMEOUT			15000	// in msec
#define NET_BROADCAST_DEGREE_MAX			1024
#define NET_BROADCAST_DEGREE_MIN			2
#define NET_SWARM_PEERLIST_FREE_DELAY		1000	// in msec
#define NET_LOCALSWRAM_EXPECTED_PEER_COUNT	8
#define NET_TIME_SAMPLE_COUNT_MIN			4
#define NET_TIME_SAMPLE_COUNT_STABLE		16
#define NET_TIME_DIFF_MAX_FOR_CASTING		30000	// in msec
#define	NET_TICK_UNIT						100		 // msec
#define	NET_TICK_UNIT_FLOAT					100.0f
#define NET_LOCAL_API_PENDCONN_COUNT		64
#define NET_LOCAL_API_MULTIPLEX_COUNT		8

#define NET_RECV_THREAD_LABEL				0x3ec50000
#define NET_LOCAL_ADDRESS_MAXCOUNT			32
#define NET_PACKET_OBFUSCATION_MAXHEADBYTE	0x30

#define NET_TUNNEL_DIRECT_MAXCOUNT			2
#define NET_TUNNEL_BOUNCER_MAXCOUNT			4
#define NET_TUNNEL_CONNECT_INTERVAL			5	// in tick unit time (100 ms)

#define NET_RELAY_PACKET_HEADBYTE_V6		'{'
#define NET_RELAY_PACKET_HEADBYTE_V4		'<'
#define NET_FORWARD_PACKET_HEADBYTE_V6		'}'
#define NET_FORWARD_PACKET_HEADBYTE_V4		'>'

#define NET_PACKET_HEADBYTE_MLT				'='
#define NET_PACKET_HEADBYTE_DHT				'd'
#define NET_PACKET_HEADBYTE_LSM				'l'
#define NET_PACKET_HEADBYTE_LSM_BROADCAST	'b'
#define NET_PACKET_HEADBYTE_GDP				'g'
#define NET_TIMESTAMP_UNIT_SHIFT			5


// define NET_BROADCAST_ALLPEERS to force forward to all peers in SMB broadcast SwarmBroadcast::Broadcast, recommended on desktops
inline const char* NET_BUILD_INFO(){ return "version 1.1, build " __DATE__ " " __TIME__; }

#if defined(OXD_NET_DEBUG_REPORT)
#define NET_DEBUG_LOG(x)	{_LOGC(x)}
#else
#define NET_DEBUG_LOG(x)	{}
#endif

