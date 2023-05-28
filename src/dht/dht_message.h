#pragma once

#include "../netsvc_types.h"
#include "dht_base.h"


namespace upw
{

struct DhtNodeBase: public Peer
{
	int		last_recv;
	int		last_sent;
	int		discover_time;
	float	latency_average;	// avg

	void	UpdateLatency(float latency);
	void	UpdateLatency(int latency){ UpdateLatency((float)latency); }
	bool	IsSlow(float good_lantency_bar) const { return latency_average > good_lantency_bar; }
};

enum DhtTxJoinSwarmEventIds
{
	DHT_SWARM_JOINING = 1,
	DHT_SWARM_DROPPING,
};

typedef void (*DhtSwarmEventCallback)(LPVOID cookie, UINT swarm_id, const DhtNodeBase& node, DhtTxJoinSwarmEventIds eid);

enum _tagMessageFields
{
	MSGFIELD_A_ID				= 0x00000001,
	MSGFIELD_R_ID				= 0x00000002,
	MSGFIELD_Y					= 0x00000020,
	MSGFIELD_Q					= 0x00000040,
	MSGFIELD_TRANSID_REPLY		= 0x00000080,
	MSGFIELD_TRANSID			= 0x00000100,
	MSGFIELD_NODES				= 0x00000200,
	MSGFIELD_PEERS				= 0x00000400,	// values in GETPEERS
	MSGFIELD_TOKEN				= 0x00000800,	// token in GETPEERS
	MSGFIELD_EXTERNAL_IPV4		= 0x00001000,

	MSGFIELD_PEER_VERSION		= 0x00004000,
	MSGFIELD_TARGET				= 0x00008000,	// Target in FINDNODE
	MSGFIELD_INFOHASH			= 0x00010000,	// info_hash in GETPEERS/ANNOUNCEPEER
	MSGFIELD_ANNOUNCE_PORT		= 0x00020000,	// "implied_port"/"port" in ANNOUNCE_PEER
	MSGFIELD_APPTAG				= 0x00040000,	// "app"
	MSGFIELD_NODEDESC			= 0x00080000,
	MSGFIELD_EXTERNAL_IPV6		= 0x00100000,
	MSGFIELD_NODES6				= 0x00200000,
	MSGFIELD_ALTERNATIVE_IPV4	= 0x00400000,	// altip in GETPEERS/PING
	MSGFIELD_ALTERNATIVE_IPV6	= 0x00800000,	
	MSGFIELD_PRIVATESWARM_PNUM	= 0x01000000,	// "pspn"

	MSGFIELD_CLOAK_IPV4			= 0x02000000,	// "cip4"
	MSGFIELD_CLOAK_IPV6			= 0x04000000,	// "cip6"
	MSGFIELD_ALTVALS			= 0x08000000,	// "altvals" in GETPEERS reply

	MSGFIELD_ESSENCE = MSGFIELD_Y|MSGFIELD_TRANSID
};

enum _tagReplyQTag
{
	RQTAG_MASK_PLUS				= 0x1,
	RQTAG_MASK_VERB				= 0xe,
	RQTAG_MASK_TXTYPE			= 0xf << 4,

	RQTAG_VERB_PLUS				= 1,
	RQTAG_VERB_PING				= 0,
	RQTAG_VERB_PING_PLUS		= 0|RQTAG_VERB_PLUS,	// reply of ping that considering the node is a peer introduced by others
	RQTAG_VERB_FINDNODE			= 2,
	RQTAG_VERB_GETPEERS			= 4,	
	RQTAG_VERB_GETPEERS_PLUS	= 4|RQTAG_VERB_PLUS,	// reply of get_peers that considering the node is a peer introduced by others
	RQTAG_VERB_ANNOUNCEPEER		= 6,

	RQTAG_TXTYPE_ROUTING		= 0 << 4,
	RQTAG_TXTYPE_FINDNODE		= 1 << 4,
	RQTAG_TXTYPE_GETPEERS		= 2 << 4,
	RQTAG_TXTYPE_JOINSWARM		= 3 << 4,
	RQTAG_TXTYPE_CONNSWARM		= 4 << 4,
};

enum _tagReqQTag
{
	REQ_PING			= 0x676e6970,
	REQ_GET_PEER		= 0x5f746567,
	REQ_FIND_NODE		= 0x646e6966,
	REQ_ANNOUNCE_PEER	= 0x6f6e6e61
};

struct DhtMessageParse
{
#pragma pack(push,1)
	typedef IPv4 dht_compact_host;
	struct dht_compact_node
	{	DhtAddress			DhtAddress;
		dht_compact_host	NetAddress;
	};
	typedef IPv6 dht_compact_host_v6;
	struct dht_compact_node_v6
	{
		DhtAddress			DhtAddress;
		dht_compact_host_v6	NetAddress;
	};
#pragma pack(pop)
	static_assert(sizeof(DhtMessageParse::dht_compact_host) == 6, "Size of DhtMessageParse::dht_compact_host should be 6");
	static_assert(sizeof(DhtMessageParse::dht_compact_host_v6) == 18, "Size of DhtMessageParse::dht_compact_host_v6 should be 18");
	struct recv_data
	{	
		LPCSTR	msg;
		UINT	msg_len;
		WORD	trans_token[2];
	};
	// All Data Members
	DWORD	fields_parsed;
	int		y;			// type of message
	DWORD	q;			// first 4 BYTE of the value of q key (_tagReqQTag)
	union
	{	struct // reply messages, MSGFIELD_TRANSID_REPLY
		{	UINT		reply_transId_verb;
			UINT		reply_transId_txtype;
			UINT		reply_transId_tx;
			UINT		reply_transId_tick;
			union {
			IPv4		reply_extern_ip_v4;	// MSGFIELD_EXTERNAL_IPV4
			IPv6		reply_extern_ip_v6;	// MSGFIELD_EXTERNAL_IPV6
			};
		};
		struct // query message, MSGFIELD_TRANSID && !MSGFIELD_TRANSID_REPLY
		{	LPCSTR		query_transId;
			UINT		query_transId_length;
		};
	};
	union
	{	DhtAddress		a_id;	// MSGFIELD_A_ID
		DhtAddress		r_id;	// MSGFIELD_R_ID
	};

	// Cloak ip
	union
	{	CloakedIPv4*	cip_v4;	// MSGFIELD_CLOAK_IPV4
		CloakedIPv6*	cip_v6;	// MSGFIELD_CLOAK_IPV6
	};

	// Version/Implementation
	LPCSTR				version;
	UINT				version_length;

	// Target for Find Node
	union {
	const DhtAddress*	target;
	const DhtAddress*	info_hash;
	};

	// Token for reply GET_PEERS, MSGFIELD_TOKEN
	LPCSTR				token;
	UINT				token_length;

	// Port for announce peer
	int					announced_port;

	// App Tag
	DWORD				app_tag;

	// Swarm Joined
	bool				swarm_member;	// only available in GetPeers reply

	// Node Desc for swarm node only
	NetworkNodeDesc		node_desc;		// MSGFIELD_NODEDESC
	union {
	IPv4				alternative_ip_v4;		// MSGFIELD_ALTERNATIVE_IPV4
	IPv6				alternative_ip_v6;		// MSGFIELD_ALTERNATIVE_IPV6
	};

	NetworkAddress		node_alt_ip;	// MSGFIELD_ALTERNATIVE_IP
	
	// private swarm packet num
	ULONGLONG			private_swarm_packet_num;

	// ping/leave
	bool				leaving_by_ping; // always parsed (no _tagMessageFields for this)
	
	////////////////////////////////////////////////////
	// It is possible that the packet includes both MSGFIELD_NODES and MSGFIELD_PEERS
	// Compact Nodeinfo, MSGFIELD_NODES
	const dht_compact_node*		nodes;
	UINT						nodes_size;
	const dht_compact_node_v6*	nodes6;
	UINT						nodes6_size;

	// Compact Peerinfo, MSGFIELD_PEERS
	NetworkAddress		peers[DHT_MESSAGE_PEERINFO_MAXCOUNT];
	UINT				peers_count;

	// Compact Peerinfo, MSGFIELD_ALTVALS
	NetworkAddress		alt_peers[DHT_MESSAGE_PEERINFO_MAXCOUNT];
	UINT				alt_peers_count;
	
	bool	ParsePacket(const recv_data& rd, bool bViaIpv4 = true);
	float GetLatency(UINT tick) const 
	{	return (fields_parsed&MSGFIELD_TRANSID_REPLY)?(float)rt::max(0, (int)tick - (int)reply_transId_tick):-1;
	}
	bool MatchReplyTransIdVerb(DWORD x) const 
	{	ASSERT(fields_parsed&MSGFIELD_TRANSID_REPLY);
		return x == (reply_transId_verb&RQTAG_MASK_VERB);
	}
	bool IsReplyTransIdPlus() const
	{	ASSERT(fields_parsed&MSGFIELD_TRANSID_REPLY);
		return reply_transId_verb&RQTAG_MASK_PLUS;
	}
};

struct DhtTxReplyContext
{
	UINT						tick;
	DhtMessageParse			msg;
	const PacketRecvContext*	recvctx;
	int							distance;
	float GetLatency() const { return msg.GetLatency(tick); }
	bool  IsPingReply() const { return msg.MatchReplyTransIdVerb(RQTAG_VERB_PING); }
};

extern bool BencodeToString(LPCSTR bencode, UINT len, LPSTR outbuf, UINT* outbuf_len);  // return false if it is ill-formated

class DhtSpace;

struct DhtMessageCompose
{
	friend class DhtTxSwarm;
	friend class DhtTxJoinSwarm;
	friend class DhtTxConnSwarm;
	rt::String		__QueryMessageFoot;
	rt::Randomizer	__RNG;

protected:
	DhtAddress		_NodeId;
	UINT			_Tick;
	WORD			_TransToken[2]; // [0] current, [1] previous
	static DWORD	_AppTag;
	static DWORD	_DhtVer;
	void			_ChangeToken();

public:
	const DhtAddress&	GetNodeId() const { return _NodeId; }
	UINT				GetTick() const { return _Tick; }

public:
	DhtMessageCompose();

	// Message Composing DHT
	UINT ComposeQueryPing(LPSTR buf, UINT bufsize, DWORD rqtag, int tx);
	UINT ComposeQueryPing(LPSTR buf, UINT bufsize, const IPv6& this_na, DWORD rqtag, int tx);
	UINT ComposeQueryFindNode(LPSTR buf, UINT bufsize, const DhtAddress& target, DWORD rqtag, int tx);
	UINT ComposeQueryGetPeer(LPSTR buf, UINT bufsize, const DhtAddress& target, DWORD rqtag, int tx, bool swmb = false);
	UINT ComposeQueryGetPeer(LPSTR buf, UINT bufsize, const DhtAddress& target, const NetworkNodeDesc& nd, const NetworkAddress& altip, DWORD rqtag, int tx, bool swmb = false);
	UINT ComposeQueryAnnouncePeer(LPSTR buf, UINT bufsize, const DhtAddress& target, WORD port, const NetworkNodeDesc& nd, LPCVOID token, UINT token_size, DWORD rqtag, int tx);

	UINT ComposeReplyPing(LPSTR buf, UINT bufsize, LPCSTR transid, UINT transid_len, const NetworkAddress& to);
	UINT ComposeReplyPing(LPSTR buf, UINT bufsize, LPCSTR transid, UINT transid_len, const IPv6& this_na, const NetworkAddress& to);
	UINT ComposeReplyFindNode(LPSTR buf, UINT bufsize, LPCSTR transid, UINT transid_len, const DhtSpace* dht, const DhtAddress& target, const NetworkAddress& to);
};

} // namespace upw
