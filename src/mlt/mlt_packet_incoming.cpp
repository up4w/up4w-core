#include "../netsvc_core.h"

#include "mlt_packet_cipher.h"

#include "mlt_packet.h"

#include "mlt_packet_incoming.h"


namespace upw
{

bool MLT_IncomingPacketParser::ParseBody(const MLT_TunnelCipherSecret &secret)
{
	if(!IsHeaderValid())
		return false;

	if(!_decipheredBodyBuffer.DecipherFromPacket(_pBody, _bodyLen, secret))
		return false;

	uint16_t plainBodyLen = _decipheredBodyBuffer.GetLength();
	uint8_t *pPlainBody = _decipheredBodyBuffer.GetBuffer();

	if(plainBodyLen < sizeof(MLT_Packet::PKT_PLAIN_BODY_HEADER))
		return false;

	_pBodyHeader = (MLT_Packet::PKT_PLAIN_BODY_HEADER *)pPlainBody;

	uint16_t curOffset = sizeof(MLT_Packet::PKT_PLAIN_BODY_HEADER);

	if(_pBodyHeader->flags & uint8_t(MLT_Packet::PKT_PLAIN_BODY_HEADER::FlagBits::WithQoSData))
	{
		if(curOffset + sizeof(MLT_Packet::PKT_LINK_QOS_DATA) > plainBodyLen)
			return false;
		_pQosData = (MLT_Packet::PKT_LINK_QOS_DATA *)(pPlainBody + curOffset);
		curOffset += sizeof(MLT_Packet::PKT_LINK_QOS_DATA);
	}
	else
		_pQosData = nullptr;

	if(_pBodyHeader->flags & uint8_t(MLT_Packet::PKT_PLAIN_BODY_HEADER::FlagBits::WithTunnelData))
	{
		_pTunnelData = pPlainBody + curOffset;
		_tunnelDataLen = plainBodyLen - curOffset;					// rest of the packet body all belong to tunnel data
		curOffset = plainBodyLen;
	}
	else
	{
		_pTunnelData = nullptr;
		_tunnelDataLen = 0;
	}

	return true;
}

MLT_IncomingPacketParser::MLT_IncomingPacketParser(const uint8_t *pPacket, uint16_t packetLen)
	: _bIsValid(false)
	, _pPacket(pPacket)
	, _packetLen(packetLen)
{
	if(_packetLen < sizeof(MLT_Packet::PKT_HEADER_COMMON))
		return;
	const MLT_Packet::PKT_HEADER_COMMON *pHeader = (const MLT_Packet::PKT_HEADER_COMMON *)_pPacket;
	if(pHeader->MAGIC != NET_PACKET_HEADBYTE_MLT)
		return;
	if(pHeader->version != 0)
		return;
	if(pHeader->flags & uint8_t(MLT_Packet::PKT_HEADER_COMMON::FlagBits::WithConnectionData))
	{
		if(_packetLen < offsetof(MLT_Packet::PKT_HEADER_WDATA, data))
			return;
		const MLT_Packet::PKT_HEADER_WDATA *pHeaderWD = (const MLT_Packet::PKT_HEADER_WDATA *)_pPacket;
		uint16_t headerLen = offsetof(MLT_Packet::PKT_HEADER_WDATA, data) + pHeaderWD->dataLen;
		if(_packetLen < headerLen)
			return;
		_bWithConnectionData = true;
		_tunnelId = pHeaderWD->recipientTunnelId;
		_connectionDataLen = pHeaderWD->dataLen;
		_connectionData = _connectionDataLen ? pHeaderWD->data : 0;
		_appId = pHeaderWD->appId;
		_pBody = _pPacket + headerLen;
		_bodyLen = _packetLen - headerLen;
	}
	else
	{
		if(_packetLen < sizeof(MLT_Packet::PKT_HEADER_WID))
			return;
		const MLT_Packet::PKT_HEADER_WID *pHeaderWID = (const MLT_Packet::PKT_HEADER_WID *)_pPacket;
		uint16_t headerLen = sizeof(MLT_Packet::PKT_HEADER_WID);
		_bWithConnectionData = false;
		_tunnelId = pHeaderWID->recipientTunnelId;
		_connectionData = nullptr;
		_connectionDataLen = 0;
		_appId = 0;
		_pBody = _pPacket + headerLen;
		_bodyLen = _packetLen - headerLen;
	}

	_packetPreCrc = os::crc32c(_pPacket, offsetof(MLT_Packet::PKT_HEADER_COMMON, crc32));
	static const decltype(((MLT_Packet::PKT_HEADER_COMMON*)(0))->crc32) zero = 0;
	_packetPreCrc = os::crc32c(&zero, sizeof(zero), _packetPreCrc);
	uint16_t restPacketOffset = offsetof(MLT_Packet::PKT_HEADER_COMMON, crc32) + sizeof(((MLT_Packet::PKT_HEADER_COMMON*)(0))->crc32);
	if(restPacketOffset < _packetLen)
		_packetPreCrc = os::crc32c(_pPacket + restPacketOffset, _packetLen - restPacketOffset, _packetPreCrc);

	_bIsValid = true;
}

const uint8_t* MLT_IncomingPacketParser::GetConnectionData()
{
	return IsHeaderValid() ? _connectionData : nullptr;
}

uint16_t MLT_IncomingPacketParser::GetConnectionDataLen()
{
	return IsHeaderValid() ? _connectionDataLen : 0;
}

uint8_t MLT_IncomingPacketParser::GetAppId()
{
	return IsHeaderValid() ? _appId : 0;
}

const uint8_t* MLT_IncomingPacketParser::GetBody()
{
	return IsHeaderValid() ? _pBody : nullptr;
}

uint16_t MLT_IncomingPacketParser::GetBodyLen()
{
	return IsHeaderValid() ? _bodyLen : 0;
}

bool MLT_IncomingPacketParser::VerifyCrcWithTunnelUID(const MLT_TunnelPDUID &uid)
{
	if(!IsHeaderValid())
		return false;

	uint32_t expectedCrc = ((MLT_Packet::PKT_HEADER_COMMON*)_pPacket)->crc32;

	return os::crc32c(&uid, MLT_TunnelPDUID::LEN, _packetPreCrc) == expectedCrc;
}

} // namespace upw
