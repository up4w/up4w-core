#include "mrc_credential.h"
#include "mrc_message.h"


namespace upw
{

namespace _details
{

class MrcMessageProofOfWork
{
	BYTE		_Workspace[64];
	void		_CalcSha512(const MrcMessage& dag_packet)
				{
					auto& h = GetSha512Hasher();
					h.Update(&dag_packet.Ver, offsetof(MrcMessage, PowNonce));
					h.Update(&dag_packet.Parents, sizeof(MrcMsgHash) * dag_packet.GetParentCount());

					auto& e = dag_packet.GetEnvelope();
					h.Update(&e, e.GetSize());
					h.Finalize(_Workspace);
				}
public:
	uint64_t	SearchNonce(const MrcMessage& dag_packet)
				{
					_CalcSha512(dag_packet);
					MrcPowDifficulty pow(dag_packet.GetPowHashCount());
					return pow.SearchNonce(_Workspace);
				}
	bool		IsValid(const MrcMessage& dag_packet)
				{
					_CalcSha512(dag_packet);
					MrcPowDifficulty pow(dag_packet.GetPowHashCount());
					return pow.IsFulfilled(_Workspace, dag_packet.PowNonce);
				}
};

thread_local MrcMessageProofOfWork MsgPow;
} // namespace _details

bool MrcMessage::IsValidPow() const
{
	return _details::MsgPow.IsValid(*this);
}

void MrcMessage::CalcPow()
{
	PowNonce = _details::MsgPow.SearchNonce(*this);
}

uint32_t MrcMessage::GetMessageCrc() const
{
	return MrcMsgHashToMsgCrc(GetHashValue());
}

MrcMessage* MrcMessage::Clone(const MrcMessage& packet) {
	UINT size = packet.GetSize();
	MrcMessage* mem = (MrcMessage*)_Malloc32AL(BYTE, size);
	memcpy(mem, &packet, size);
	return mem;
};

bool MrcMessage::IsValidSize(int packet_size)
{
	UINT sz = packet_size - (offsetof(MrcMessage, Parents) + (GetParentCount() * sizeof(MrcMsgHash)));
	return (packet_size > offsetof(MrcMessage, Parents))
		&& (Ver == MRC_PACKETS_VERSION)
		&& (GetEnvelope().VerifySize(sz) == true)
		;
}

MrcMsgHash MrcMessage::GetHashValue() const
{
	BYTE _buf[32];

	HashCalculate(this, GetSize(), _buf);
	return *(MrcMsgHash*)_buf;
}

void MrcMessage::Dump(rt::String& out, MrcMsgHash* hash) const
{
	MrcMsgHash h;

	if(hash == nullptr)
	{
		h = GetHashValue();
	}
	else
	{
		h = *hash;
	}

	out = rt::SS("[") + rt::tos::Base32CrockfordOnStack<>(h) + rt::SS("] --- ");
	for(UINT i = 0; i < GetParentCount(); i++)
		out += rt::SS("<") + rt::tos::Base32CrockfordOnStack<>(Parents[i]) + rt::SS(">");

	int64_t tm = GetTime();
	out += rt::SS("  tm:") + rt::tos::Number(tm);
}

int MrcHeader::CheckOpCode(const void* buf)
{ 
	auto* header = (MrcHeader*)buf;
	if(header->Magic != MRC_PROTOCOL_CHAR_MAIN_SWARM) return -1;

	switch (header->OpCode)
	{
	case MrcHeader::OP_MESSAGE_PULL:
	case MrcHeader::OP_MESSAGE_CONTENT:
	case MrcHeader::OP_STATUS_PING:
	case MrcHeader::OP_STATUS_PONG:
	case MrcHeader::OP_FRAGMENT_DATA:
		return header->OpCode;
	default:
		return -1;
	}
}

uint32_t MrcEnvelope::GetSize() const
{
	uint32_t ret = offsetof(MrcEnvelope, CredentialData);
	ret += GetCredentialSize();

	uint32_t iter;
	auto* pld = GetFirstPayload(iter);
	while(pld)
	{
		ret += pld->GetSize();
		pld = GetNextPayload(pld, iter);
	}

	return ret;
}

NonceData& MrcEnvelope::GetNonce()
{
	ASSERT(HasNonce());
	return GetCredential<MrcCredential_SealedBox>().Nonce;
}

UINT MrcEnvelope::GetCredentialSize() const
{
	switch(GetType())
	{
	case EVLP_SEALBOX:			return GetCredential<MrcCredential_SealedBox>().GetSize();
	case EVLP_SEALGREETING:		return GetCredential<MrcCredential_SealedGreeting>().GetSize();
	case EVLP_BROADCAST:		return GetCredential<MrcCredential_Broadcast>().GetSize();
	case EVLP_COMMUNITYSEND:	return GetCredential<MrcCredential_CommunitySend>().GetSize();
	default:					return 0x7fffffff;
	}
}

bool MrcEnvelope::VerifySize(UINT len) const
{
	uint32_t ret = offsetof(MrcEnvelope, CredentialData);
	if(ret >= len)return false;

	ret += GetCredentialSize();
	if(ret > len)return false;

	uint32_t iter;
	auto* pld = GetFirstPayload(iter);
	while(pld)
	{
		ret += pld->GetSize();
		if(ret > len)return false;
		pld = GetNextPayload(pld, iter);
	}

	return ret == len;
}

const MrcCipherPayload* MrcEnvelope::GetFirstPayload(uint32_t& iter) const
{
	auto* ret = (MrcCipherPayload*)&CredentialData[GetCredentialSize()];
	iter = Type_CPLD&CipherPayloadTypeBitmask;

	DWORD type_bit = 1<<ret->GetType();
	if(iter&type_bit)
	{	iter &= ~type_bit;
		return ret;
	}

	return nullptr;
}

const MrcCipherPayload* MrcEnvelope::GetNextPayload(const MrcCipherPayload* p, uint32_t& iter) const
{
	if(iter == 0)return nullptr;

	auto* ret = (const MrcCipherPayload*)(((LPCBYTE)p) + p->GetSize());
	uint32_t type_bit = 1<<ret->GetType();
	if(iter&type_bit)
	{	iter &= ~type_bit;
		return ret;
	}

	return nullptr;
}

const MrcCipherPayload* MrcEnvelope::GetPayload(MrcCipherPayload::Type t) const
{
	uint32_t iter;
	auto* pld = GetFirstPayload(iter);
	while(pld)
	{
		if(pld->GetType() == t)return pld;
		pld = GetNextPayload(pld, iter);
	}

	return nullptr;
}

bool MrcEnvelope::MatchContactPoint(const ext::fast_set<MrcContactPointNum>& cps)
{
	auto type = GetType();
	switch(type)
	{
	case EVLP_SEALBOX:
		{	auto& SealedBox = GetCredential<MrcCredential_SealedBox>();
			for(UINT i=0; i<SealedBox.RecipientCount; i++)
				if(cps.has(SealedBox.Recipients[i].ContactPoint))
					return true;
		}
		break;
	case EVLP_SEALGREETING:
		{	auto& SealedGreeting = GetCredential<MrcCredential_SealedGreeting>();
			if(cps.has(SealedGreeting.ContactPoint.ContactPoint))
				return true;
		}
		break;
	case EVLP_BROADCAST:
		{	auto& Broadcast = GetCredential<MrcCredential_SealedGreeting>();
			if(cps.has(Broadcast.ContactPoint.ContactPoint))
				return true;
		}
		break;
	default: 
		ASSERT(0);
	}

	return false;
}

} // namespace upw
