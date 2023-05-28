#pragma once
#include <shared_mutex>

#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_common.h"

#include "mlt_packet_cipher.h"


namespace upw
{

class MLT_IncomingPacketParser
{
private:
	// header
	bool									_bIsValid = false;
	const uint8_t							*_pPacket = nullptr;
	uint16_t								_packetLen = 0;

	bool									_bWithConnectionData = false;
	uint32_t								_tunnelId = 0xffffffff;		// ignored if connectionData is not nullptr
	const uint8_t							*_connectionData = nullptr;
	uint16_t								_connectionDataLen = 0;
	uint8_t									_appId = 0;

	const uint8_t							*_pBody = nullptr;
	uint16_t								_bodyLen = 0;

	uint32_t								_packetPreCrc = 0;			// crc32 of the packet with crc32 field set to 0

	// body
	MLT_PlainBodyBuffer						_decipheredBodyBuffer;

	const MLT_Packet::PKT_PLAIN_BODY_HEADER	*_pBodyHeader = nullptr;
	const MLT_Packet::PKT_LINK_QOS_DATA		*_pQosData = nullptr;

	const uint8_t							*_pTunnelData = nullptr;
	uint16_t								_tunnelDataLen = 0;

public:
	MLT_IncomingPacketParser(const uint8_t *pPacket, uint16_t packetLen);
	const bool HasConnectionData() { return _bWithConnectionData; }
	const uint8_t* GetConnectionData();
	uint16_t GetConnectionDataLen();
	uint8_t GetAppId();
	uint32_t GetTunnelId() { return _tunnelId; }

	const uint8_t* GetBody();
	uint16_t GetBodyLen();

	bool VerifyCrcWithTunnelUID(const MLT_TunnelPDUID &uid);
	bool IsHeaderValid() { return _bIsValid; }

	bool ParseBody(const MLT_TunnelCipherSecret &secret);

	const MLT_Packet::PKT_PLAIN_BODY_HEADER* GetBodyHeader() const { return _pBodyHeader; }
	const MLT_Packet::PKT_LINK_QOS_DATA* GetQosData() const { return _pQosData; }
	bool RequestsHeartbeatReply() const { return _pBodyHeader->flags & uint8_t(MLT_Packet::PKT_PLAIN_BODY_HEADER::FlagBits::RequestHeartbeatReply); }

	const uint8_t* GetTunnelData() const { return _pTunnelData; }
	uint16_t GetTunnelDataLen() const { return _tunnelDataLen; }
};

} // namespace upw