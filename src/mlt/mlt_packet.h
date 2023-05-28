#pragma once
#include <shared_mutex>

#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_common.h"


namespace upw
{

class MLT_Packet
{
public:
#pragma pack(push, 1)
	struct PKT_HEADER_COMMON
	{
		enum class FlagBits : uint8_t
		{
			WithConnectionData = 1 << 0,		// tunnel id on recipient's side is unknown, hence sending the connection data, the header is a PKT_HEADER_WITH_CONNECTION_DATA instead of PKT_HEADER
		};
		char			MAGIC;					// NET_PACKET_HEADBYTE_MLT, i.e. '='
		uint8_t			flags;					// from FlagBits
		uint16_t		version;				// version of MLT protocol
		uint32_t		crc32;					// crc32(packet + TunnelId). packet = the whole packet but with this crc32 set to 0
												// IMPORTANT: TunnelId must be after the packet in this crc calculation, otherwise there's a vulnerability.
												//            i.e. crc32(TunnelId + packet) = crc32(packet, init_crc = crc32(TunnelId)), now the attacker can enumerate 32-bit integers to find crc32(TunnelId).
	};

	struct PKT_HEADER_WID : public PKT_HEADER_COMMON
	{
		uint32_t		recipientTunnelId;		// tunnel id used by the recipient to identify the tunnel, 0xffffffff if unknown
	};
	static_assert(sizeof(PKT_HEADER_COMMON) == offsetof(PKT_HEADER_WID, recipientTunnelId), "struct PKT_HEADER_WID having unexpected size");

	struct PKT_HEADER_WDATA : public PKT_HEADER_COMMON
	{
		uint32_t		recipientTunnelId;		// tunnel id used by the recipient to identify the tunnel, 0xffffffff if unknown
		uint16_t		dataLen;				// length of connection data
		uint8_t			appId;					// appId of the tunnel
		uint8_t			data[1];				// connection data
	};
	static_assert(sizeof(PKT_HEADER_COMMON) == offsetof(PKT_HEADER_WDATA, recipientTunnelId), "struct PKT_HEADER_WDATA having unexpected size");

	struct PKT_PLAIN_BODY_HEADER				// hash-checked, encrypted, follows PKT_HEADER_*
	{
		enum class FlagBits : uint8_t
		{
			WithQoSData				= 1 << 0,			// the packet includes PKT_LINK_QOS_DATA
			WithTunnelData			= 1 << 1,			// the packet includes TUNNEL_DATA
			RequestHeartbeatReply	= 1 << 2,			// the packet requests an immediate heartbeat reply
		};
		uint64_t		senderSessionId;		// session id of the sender
		uint64_t		recipientSessionId;		// session id of the recipient
		uint8_t			flags;					// from FlagBits
		uint32_t		senderTunnelId;			// tunnel id used by the sender, recipient should give this value to PKT_HEADER.tunnelId when sending packets in this tunnel
		uint32_t		senderLinkId;			// link id used by the sender, recipient should give this value to PKT_HEADER_LINK.tunnelId when sending packets in this link
		uint32_t		recipientLinkId;		// link id used by the recipient to identify the link, 0xffffffff if unknown
	};

	struct PKT_LINK_QOS_DATA
	{
		// LPSN = per-Link Packet Serial Number
		// Any packet sent by the sender over this link increments it by 1, received packets don't count.
		// Each side of the link maintains its own SN.
		uint32_t		LPSN;					// SN of the packet on the sender's side, 0xffffffff to exclude this packet from QoS report, i.e. the sender does not need the receiver to ACK it.
		uint32_t		ackLPSNBase;			// the largest serial number of the packet that the sender ever received from the recipient
		uint64_t		ackLPSNMask;			// bit mask of whether the 64 packets with SN counting from ackLPSNBase, ackLPSNBase - 1, ... sent by recipient were received by the sender
	};

	// Tunnel-level packets
	struct PKT_TUNNEL_DATA_HEADER				// 
	{
		// TPSN = per-Tunnel Packet Serial Number
		// Any TunnelData packet sent by the sender over this tunnel increments it by 1, received packets don't count. 
		// Same tunnel data sent over several links at the same time count only once.
		// Each side of the tunnel maintains its own SN.
		uint32_t		TPSN;					// 0xffffffff to indicate that an ACK is not needed
		uint32_t		WaitingAckSN;			// sender still waiting for ACK of packets with SN >= WaitingSN.

		enum class TunnelDataType : uint8_t
		{
			AccessPoints = 0,					// access points that the destination wants to add to the links
			Close = 1,							// the destination wants to close the link
			MessageDataSlice = 2,				// a slice of message data from sender to receiver
			MessageAcknowledge = 3,				// sent by the message-receiver to message-sender to acknowledge receiving the whole message
			MessageReject = 4,					// sent by the message-receiver to message-sender to reject the message for whatever reason
			Empty = 5,							// packet is sent without tunnel data
			FileRequestBlock = 6,				// request a file block from the file-sender
			FileRejectRequest = 7,				// sent by the file-sender to file-receiver to reject a file request for whatever reason
			FileSlice = 8,						// sending a slice of a file to the file-receiver
			FileAcknowledge = 9,				// sent by the file-receiver to acknowledge that a file has been successfully received
			FileCancelRequest = 10,				// sent by the file-receiver to cancel a previous request, this cancels not only a single block request, but the whole request with the same id
			BatchAck = 11,						// sent to acknowledge received packets
			Max = 255,
		};
		TunnelDataType	dataType;
	};

	struct PKT_ADD_ACCESS_POINTS : public PKT_TUNNEL_DATA_HEADER	// hash-checked, encrypted
	{
		NodeAccessPoints accessPoints;
	};

	struct PKT_MESSAGE_DATA_SLICE : public PKT_TUNNEL_DATA_HEADER
	{
		constexpr static uint32_t	messageSliceSize = 1280;			// number of bytes in a slice
		uint32_t		msgId;				// id of the file
		uint32_t		msgTotalLen;		// total size of the message
		uint32_t		sliceIdx;			// slice idx within the file
		uint8_t			slice[1];			// slice data
	};

	struct PKT_MESSAGE_ACKNOWLEDGE : public PKT_TUNNEL_DATA_HEADER
	{
		uint32_t		msgId;
	};

	struct PKT_MESSAGE_REJECT : public PKT_TUNNEL_DATA_HEADER
	{
		uint32_t		msgId;
	};

	struct PKT_FILE_SLICE : public PKT_TUNNEL_DATA_HEADER
	{
		constexpr static uint32_t	fileSliceSize = 1280;			// number of bytes in a slice
		uint32_t		fileId;			// id of the file
		uint32_t		sliceIdx;		// slice idx within the file
		uint8_t			slice[1];		// slice data
	};

	struct PKT_FILE_REQUEST_BLOCK : public PKT_TUNNEL_DATA_HEADER
	{
		constexpr static uint32_t	fileNumSlicesPerBlock = 1280 * 8;	// number of slices per block
		constexpr static uint32_t	fileBlockSize = fileNumSlicesPerBlock * PKT_FILE_SLICE::fileSliceSize;	// number of bytes per block
		uint8_t			fileHash[32];	// hash of the file
		uint64_t		fileSize;		// size of the file
		uint32_t		fileId;			// an id that the receiver could use to indicate this request when sending data answering for the request
		uint32_t		priority;		// priority of the request (at file level), requests with higher value should be processed first
		uint32_t		blockIdx;		// block index within the file
		uint8_t			sliceMask[fileNumSlicesPerBlock / 8];	// whether the sender has each slice already, 0 for needed.
	};

	struct PKT_FILE_CANCEL_REQUEST : public PKT_TUNNEL_DATA_HEADER
	{
		uint32_t		fileId;			// an id that the receiver could use to indicate this request when sending data answering for the request
	};

	struct PKT_FILE_REJECT_REQUEST : public PKT_TUNNEL_DATA_HEADER
	{
		uint32_t		fileId;			// id of the file, as in the received PKT_FILE_REQUEST_BLOCK packet
		uint32_t		blockIdx;		// block index of the file, as in the received PKT_FILE_REQUEST_BLOCK packet
	};

	struct PKT_FILE_ACKNOWLEDGE : public PKT_TUNNEL_DATA_HEADER
	{
		uint32_t		fileId;			// id of the file
	};

	struct PKT_BATCH_ACK : public PKT_TUNNEL_DATA_HEADER
	{
		uint32_t		SNBegin;					// The first SN in this batch, inclusive
		uint32_t		SNEnd;						// The last SN in this batch, inclusive
		uint32_t		lastUnackedPacketSN;		// last packet which arrived after last sent ACK, 0xffffffffu if nothing arrived, this might be outside range [SNBegin, SNEnd]
		uint16_t		lastUnackedPacketAckDelay;	// The delay from when packet lastUnackedPacketSN was received to when this batch-ack is sent
		uint32_t		firstUnackedPacketSN;		// first packet which arrived after last sent ACK, 0xffffffffu if nothing arrived, this might be outside range [SNBegin, SNEnd]
		uint16_t		firstUnackedPacketAckDelay;	// The delay from when the first packet which arrived after last sent ACK, to when this batch-ack is sent
		uint64_t		AckMask[1];					// An array of masks, 1-bits for packets to be ACKed. The mask is aligned to 64 boundary.
													// i.e. the array has size of (SNEnd / 64 - SNBegin / 64 + 1)
													//      packet SNBegin corresponds to AckMask[0] & (1 << (SNBegin % 64))
													//      packet SNEnd corresponds to AckMask[SNEnd / 64 - SNBegin / 64] & (1 << (SNEnd % 64))
		constexpr static uint32_t	AckMaskMaxSizeInBytes = 1280;	// maximum array size in bytes
		static uint16_t GetSize(uint32_t SNBegin, uint32_t SNEnd)	// calculate the size of a PKT_BATCH_ACK given its SNBegin and SNEnd, returns 0 if it's invalid
		{
			if(SNEnd < SNBegin)
				return 0;
			uint32_t ackMaskNumBytes = (SNEnd / 64 - SNBegin / 64 + 1) * 8;
			if(ackMaskNumBytes > AckMaskMaxSizeInBytes)
				return 0;
			return uint16_t(ackMaskNumBytes + offsetof(PKT_BATCH_ACK, AckMask));
		}
	};


#pragma pack(pop)

};

} // namespace upw