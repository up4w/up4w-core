#pragma once

#include "../netsvc_types.h"
#include "gdp_base.h"

namespace upw
{

const BYTE GOSSIP_MAGIC_BYTE = 'g';

enum GdpOpcode {
	GOC_NOOP = 0,
	
	GOC_MESSAGE_PULL	= 0xA1,
	GOC_MESSAGE_CONTENT,
	GOC_MESSAGE_PING,
	GOC_MESSAGE_PONG,
	
	GOC_Req_Normal	= 0x01,
	GOC_Ack_Data	= 0x11,
	GOC_Ack_Failed	= 0xF1,

	GOC_Req_Batch	= 0x02,
	GOC_Ack_Batch_Failed	= 0xF2,

	GOC_Req_Query	= 0x03,
	GOC_Ack_List	= 0x13,

	GOC_MAX
};


/*
[GdpPacketHeader]
[GDP_PACKET_KEY]
[ XXX_DS ]
*/
#pragma pack(push,1)
struct GdpPacketHeader
{
	BYTE		MAGIC;		// MUST BE GOSSIP_MAGIC_BYTE, "g"
	BYTE		OpCode;		// GOC_XXXX
};

struct GdpPacketCommon
{
	GdpPacketHeader	Header;
	GdpKey			Key;
	//BYTE			GDP_Flags;  // associated with OpCode
	//LPCVOID		GetDataPtr() { return (LPCBYTE)this + sizeof(GdpPacketCommon); };
};

struct GdpPacketReqNormal: public GdpPacketCommon
{
	BYTE			Count;
	const GdpRange*	Ranges() const { return (const GdpRange*) ( this + 1); }
};

struct GdpPacketReqBatch : public GdpPacketHeader
{
	BYTE			Count;
	const GdpKey*	Keys() { return (const GdpKey*)(this + 1); }
};

struct GdpPacketMessagePull
{
	GdpHash	Hash;
	GdpHint	Hint;

	UINT		Offset;
	WORD		Length;
};

struct GdpPacketMessageContent
{
	GdpHash	Hash;
	GdpHint	Hint;

	UINT		DataTotalSize;

	UINT		Offset;
	WORD		Length;

	BYTE		Data[1];
};
#pragma pack(pop)

extern bool GdpBuildMessagePullPacketWithHint(const GdpHash& hash, const GdpHint& hint, UINT offset, WORD len, PacketBuf<>& buf);
extern bool GdpBuildMessagePullPacketWithHint(const GdpHash& hash, const GdpHint& hint, UINT offset, WORD len, LPCBYTE data, WORD data_len, PacketBuf<>& buf);
extern bool GdpBuildMessageContentPacket(const GdpHash& hash, const GdpHint& hint, UINT total_size, UINT offset, UINT len, LPCBYTE data, PacketBuf<>& buf);

extern UINT GdpBuildPacketReqNormal(const GdpKey& key, const GdpRange* ranges, UINT count, PacketBuf<>& buf);
extern UINT GdpBuildPacketReqBatch(const GdpKey* keys, UINT count, PacketBuf<>& buf);
extern UINT GdpBuildPacketReqBatch_Append(const GdpKey& key, PacketBuf<>& buf);

}