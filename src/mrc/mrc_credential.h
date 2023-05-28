#pragma once
#include "mrc_base.h"


namespace upw
{
#pragma pack(push, 1)


struct MrcEnvelopeContactPoint
{
	MrcContactPointNum	ContactPoint;
	uint16_t			Reserved;
	uint8_t				Reserved2;
};

struct MrcRecipient
{
	static const UINT SendingUp	= 0x8000U;

	MrcContactPointNum		ContactPoint;
	uint32_t				Reserved;
	uint16_t				Flag_Direction;
	SealedCipherSecret		SealedSecret; // the lowest bit of the decrypted data of Secret indicates sending direction. 0: Sender's PK <= Recipient's, 1: Sender's PK > Recipient's

	bool IsSendingUp() const { return SendingUp&Flag_Direction; }  // Sender's Address < Recipient's Address
};

// encryption and pairing
struct MrcCredential_SealedBox
{	// master key is over raw payloads before encryption
	NonceData		Nonce;
	BYTE			RecipientCount;		// High 4bit: (RecipientCount - 1); Low 4bit: (1<<CipherPayloadType)
	MrcRecipient	Recipients[1];
	UINT			GetSize() const { return GetSize(RecipientCount); }
	static UINT		GetSize(UINT recip_co){ return offsetof(MrcCredential_SealedBox, Recipients) + sizeof(MrcRecipient)*recip_co; }
};

struct MrcCredential_SealedGreeting
{	// master key is over raw payloads before encryption
	NonceData				Nonce;
	MrcRecipient			Recipient;
	// for SP
	MrcEnvelopeContactPoint	ContactPoint;
	EncryptedCipherSecret	EncryptedSecret;
	SignatureData			Signature; // over master key
	static UINT				GetSize(){ return sizeof(MrcCredential_SealedGreeting); }
};

struct MrcCredential_Broadcast
{	// master key is over cooked payloads after encryption
	// for entity's FC endpoint
	MrcEnvelopeContactPoint	ContactPoint;
	SignatureData			Signature; // over master key
	static UINT				GetSize(){ return sizeof(MrcCredential_Broadcast); }
};

struct MrcCredential_CommunitySend
{	// master key is supplied externally, and contact* is also resolved and provided by extern
	SignatureData			Signature; // over encrypted payload
	static UINT				GetSize(){ return sizeof(MrcCredential_CommunitySend); }
};

#pragma pack(pop)
} // namespace upw
