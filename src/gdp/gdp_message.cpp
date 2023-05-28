#include "gdp_message.h"

namespace upw
{


bool GdpBuildMessagePullPacketWithHint(const GdpHash& hash, const GdpHint& hint, UINT offset, WORD len, PacketBuf<>& buf)
{
	buf.Reset();
	buf.Append(&GOSSIP_MAGIC_BYTE, 1);
	BYTE b = GOC_MESSAGE_PULL;
	buf.Append(&b, 1);

	buf.Append(hash, sizeof(hash));
	buf.Append(&hint, sizeof(hint));

	buf.Append(&offset, 4);
	buf.Append(&len, 2);

	return true;
}

bool GdpBuildMessagePullPacketWithHint(const GdpHash& hash, const GdpHint& hint, UINT offset, WORD len, LPCBYTE data, WORD data_len, PacketBuf<>& buf)
{
	buf.Append(&GOSSIP_MAGIC_BYTE, 1);
	BYTE b = GOC_MESSAGE_PULL;
	buf.Append(&b, 1);

	buf.Append(hash, sizeof(hash));
	buf.Append(&hint, sizeof(hint));

	buf.Append(&offset, 4);
	buf.Append(&len, 2);

	buf.Append(data, data_len);

	return true;
}


bool GdpBuildMessageContentPacket(const GdpHash& hash, const GdpHint& hint, UINT total_size, UINT offset, UINT len, LPCBYTE data, PacketBuf<>& buf)
{
	// check size
	if(total_size > GDP_BLOB_NONPAGED_MAXSIZE && len > GDP_PACKET_FRAGMENT_SIZE)
		return false;

	buf.Reset();
	buf.Append(&GOSSIP_MAGIC_BYTE, 1);
	BYTE b = GOC_MESSAGE_CONTENT;
	buf.Append(&b, 1);

	buf.Append(hash, sizeof(hash));
	buf.Append(&hint, sizeof(hint));

	buf.Append(&total_size, 4);

	buf.Append(&offset, 4);
	buf.Append(&len, 2);

	buf.Append(data, len);

	return true;
}



UINT GdpBuildPacketReqNormal(const GdpKey& key, const GdpRange* ranges, UINT count, PacketBuf<>& buf)
{
	buf.Reset();
	buf.AppendPOD((BYTE)GOSSIP_MAGIC_BYTE);	// Magic Byte

	buf.AppendPOD((BYTE)GOC_Req_Normal);	// OP Code

	buf.AppendPOD(key);						// Key

	count = rt::min(count, (UINT)GDP_PACKET_MAX_RANGES);

	buf.AppendPOD((BYTE)count);				// Count of Ranges

	for(UINT i = 0; i < count; i++)
		buf.AppendPOD(ranges[i]);			// Range

	return count;
}

UINT GdpBuildPacketReqBatch(const GdpKey* keys, UINT count, PacketBuf<>& buf)
{
	buf.Reset();
	buf.AppendPOD((BYTE)GOSSIP_MAGIC_BYTE);	// Magic Byte
	
	buf.AppendPOD((BYTE)GOC_Req_Batch);		// OP Code

	count = rt::min(count, (UINT)GDP_PACKET_MAX_KEYS);

	buf.AppendPOD((BYTE)count);				// Count of Keys

	for(UINT i = 0; i < count; i++)
		buf.AppendPOD(keys[i]);				// Key

	return count;
}

UINT GdpBuildPacketReqBatch_Append(const GdpKey& key, PacketBuf<>& buf)
{
	LPBYTE pCount = (LPBYTE) buf.GetData() + sizeof(GdpPacketHeader);
	BYTE& count = *pCount;
	if(count >= GDP_PACKET_MAX_KEYS)
		return count;

	count++;
	buf.AppendPOD(key);
	return count;
}

}