#include "../netsvc_core.h"

#include "mlt_packet_cipher.h"

#include "mlt_packet_outgoing.h"


namespace upw
{

void MLT_OutgoingPacketSynthesizer::SetHeader(uint32_t recipientTunnelId, uint32_t recipientLinkId, uint64_t senderSessionId, uint64_t recipientSessionId, uint32_t senderTunnelId, uint32_t senderLinkId)
{
	_bHeaderSet = true;
	_bWithConnectionData = false;
	_recipientTunnelId = recipientTunnelId;
	_recipientLinkId = recipientLinkId;
	_senderSessionId = senderSessionId;
	_recipientSessionId = recipientSessionId;
	_senderTunnelId = senderTunnelId;
	_senderLinkId = senderLinkId;
}

void MLT_OutgoingPacketSynthesizer::SetHeaderWithConnectionData(uint32_t recipientTunnelId, uint32_t recipientLinkId, const uint8_t *pConnectionData, uint16_t connectionDataLen, uint8_t appId, uint64_t senderSessionId, uint64_t recipientSessionId, uint32_t senderTunnelId, uint32_t senderLinkId)
{
	_bHeaderSet = true;
	_bWithConnectionData = true;
	_recipientTunnelId = recipientTunnelId;
	_recipientLinkId = recipientLinkId;
	_senderSessionId = senderSessionId;
	_recipientSessionId = recipientSessionId;
	_pConnectionData = pConnectionData;
	_connectionDataLen = connectionDataLen;
	_appId = appId;
	_senderTunnelId = senderTunnelId;
	_senderLinkId = senderLinkId;
}

void MLT_OutgoingPacketSynthesizer::SetQosData(uint32_t LPSN, uint32_t rcvdLPSNLargest, uint64_t rcvdLPSNMask)
{
	_bQosDataSet = true;
	_LPSN = LPSN;
	_rcvdLPSNLargest = rcvdLPSNLargest;
	_rcvdLPSNMask = rcvdLPSNMask;
}

void MLT_OutgoingPacketSynthesizer::SetTunnelData(uint8_t *pTunnelData, uint16_t tunnelDataLen)
{
	_pTunnelData = pTunnelData;
	_tunnelDataLen = tunnelDataLen;
}

void MLT_OutgoingPacketSynthesizer::SetRequestHeartbeatReplyFlag()
{
	_bRequestHeartbeatReply = true;
}

bool MLT_OutgoingPacketSynthesizer::SynthesizePacket(PacketBuf<> &outPacketBuf, const MLT_TunnelCipherSecret &secret, const MLT_TunnelPDUID &uid)
{
	if(!_bHeaderSet)
		return false;

	outPacketBuf.Reset();

	// header
	MLT_Packet::PKT_HEADER_COMMON *pHeaderCommon = nullptr;
	if(_bWithConnectionData)
	{
		MLT_Packet::PKT_HEADER_WDATA *pHeader = (MLT_Packet::PKT_HEADER_WDATA*)outPacketBuf.Claim(offsetof(MLT_Packet::PKT_HEADER_WDATA, data) + _connectionDataLen);

		pHeader->recipientTunnelId = _recipientTunnelId;
		pHeader->dataLen = _connectionDataLen;
		pHeader->appId = _appId;
		if(_pConnectionData && _connectionDataLen)
			memcpy(pHeader->data, _pConnectionData, _connectionDataLen);
		outPacketBuf.Commit(offsetof(MLT_Packet::PKT_HEADER_WDATA, data) + _connectionDataLen);

		pHeaderCommon = pHeader;
	}
	else
	{
		MLT_Packet::PKT_HEADER_WID *pHeader = (MLT_Packet::PKT_HEADER_WID*)outPacketBuf.Claim(sizeof(MLT_Packet::PKT_HEADER_WID));
		pHeader->recipientTunnelId = _recipientTunnelId;
		outPacketBuf.Commit(sizeof(MLT_Packet::PKT_HEADER_WID));

		pHeaderCommon = pHeader;
	}

	if(!pHeaderCommon)
		return false;

	pHeaderCommon->MAGIC = NET_PACKET_HEADBYTE_MLT;
	pHeaderCommon->flags = 0;
	if(_bWithConnectionData)
		pHeaderCommon->flags |= uint8_t(MLT_Packet::PKT_HEADER_COMMON::FlagBits::WithConnectionData);
	pHeaderCommon->version = 0;
	pHeaderCommon->crc32 = 0;			// overwritten later, must be 0 now to calculate the real crc32 later

	// body
	MLT_PlainBodyBuffer cb;

	MLT_Packet::PKT_PLAIN_BODY_HEADER *pBodyHeader = cb.Allocate<MLT_Packet::PKT_PLAIN_BODY_HEADER>();
	if(!pBodyHeader)
		return false;
	pBodyHeader->recipientLinkId = _recipientLinkId;
	pBodyHeader->senderSessionId = _senderSessionId;
	pBodyHeader->recipientSessionId = _recipientSessionId;
	pBodyHeader->senderTunnelId = _senderTunnelId;
	pBodyHeader->senderLinkId = _senderLinkId;
	pBodyHeader->flags = 0;

	if(_bQosDataSet)
	{
		pBodyHeader->flags |= uint8_t(MLT_Packet::PKT_PLAIN_BODY_HEADER::FlagBits::WithQoSData);
		MLT_Packet::PKT_LINK_QOS_DATA *pQosData = cb.Allocate<MLT_Packet::PKT_LINK_QOS_DATA>();
		if(!pQosData)
			return false;

		pQosData->LPSN = _LPSN;
		pQosData->ackLPSNBase = _rcvdLPSNLargest;
		pQosData->ackLPSNMask = _rcvdLPSNMask;
	}

	if(_pTunnelData && _tunnelDataLen)
	{
		pBodyHeader->flags |= uint8_t(MLT_Packet::PKT_PLAIN_BODY_HEADER::FlagBits::WithTunnelData);
		uint8_t *pTunnelData = cb.Allocate(_tunnelDataLen);
		if(!pTunnelData)
			return false;

		memcpy(pTunnelData, _pTunnelData, _tunnelDataLen);
	}

	if(_bRequestHeartbeatReply)
		pBodyHeader->flags |= uint8_t(MLT_Packet::PKT_PLAIN_BODY_HEADER::FlagBits::RequestHeartbeatReply);

	uint32_t nonce;
	sec::Randomize(nonce);
	if(!cb.CipherAndAppendToPacket(outPacketBuf, secret, nonce))
		return false;

	pHeaderCommon->crc32 = os::crc32c(outPacketBuf.GetData(), outPacketBuf.GetLength());
	pHeaderCommon->crc32 = os::crc32c(&uid, MLT_TunnelPDUID::LEN, pHeaderCommon->crc32);

	return true;
}

} // namespace upw
