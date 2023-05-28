#pragma once
#include <shared_mutex>

#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_packet.h"


namespace upw
{

class MLT_OutgoingPacketSynthesizer
{
private:
	bool			_bHeaderSet = false;
	bool			_bWithConnectionData = false;
	const uint8_t	*_pConnectionData = nullptr;
	uint16_t		_connectionDataLen = 0;
	uint8_t			_appId = 0;
	uint32_t		_recipientTunnelId = 0xffffffff;
	uint32_t		_recipientLinkId = 0xffffffff;
	uint64_t		_senderSessionId = 0xffffffffffffffffull;
	uint64_t		_recipientSessionId = 0xffffffffffffffffull;
	uint32_t		_senderTunnelId = 0xffffffffu;
	uint32_t		_senderLinkId = 0xffffffffu;

	bool			_bRequestHeartbeatReply = false;

	bool			_bQosDataSet = false;
	uint32_t		_LPSN = 0;
	uint32_t		_rcvdLPSNLargest = 0;
	uint64_t		_rcvdLPSNMask = 0;

	uint8_t			*_pTunnelData = nullptr;
	uint16_t		_tunnelDataLen = 0;

public:
	void SetHeader(uint32_t recipientTunnelId, uint32_t recipientLinkId, uint64_t senderSessionId, uint64_t recipientSessionId, uint32_t senderTunnelId, uint32_t senderLinkId);
	void SetHeaderWithConnectionData(uint32_t recipientTunnelId, uint32_t recipientLinkId, const uint8_t *pConnectionData, uint16_t connectionDataLen, uint8_t appId, uint64_t senderSessionId, uint64_t recipientSessionId, uint32_t senderTunnelId, uint32_t senderLinkId);
	void SetQosData(uint32_t LPSN, uint32_t rcvdLPSNLargest, uint64_t rcvdLPSNMask);
	void SetTunnelData(uint8_t *pTunnelData, uint16_t tunnelDataLen);
	void SetRequestHeartbeatReplyFlag();

	bool SynthesizePacket(PacketBuf<> &outPacketBuf, const MLT_TunnelCipherSecret &secret, const MLT_TunnelPDUID &uid);
};

} // namespace upw