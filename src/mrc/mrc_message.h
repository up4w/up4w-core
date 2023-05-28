#pragma once
#include "../net_types.h"
#include "../gdp/gdp_base.h"
#include "mrc_base.h"


namespace upw
{
#pragma pack(push, 1)

const int MRC_MESSAGE_PARENT_FULL_COUNT = 8;
const int MRC_MESSAGE_PARENT_HALF_COUNT = MRC_MESSAGE_PARENT_FULL_COUNT/2;
const int MRC_PACKET_BUFSIZE = NET_DATAGRAMNETWORK_MTU - NET_PACKET_PREFIX_DEFAULT_SIZE;

struct MrcHeader
{
	enum OpCodes
	{
		OP_NOOP				= 0,
		OP_MESSAGE_PULL		= 0x11,
		OP_MESSAGE_CONTENT	= 0x12,
		OP_STATUS_PING		= 0x21,
		OP_STATUS_PONG		= 0x22,
		OP_FRAGMENT_DATA	= 0x31
	};

	BYTE		Magic;				// MUST BE MRC_PROTOCOL_CHAR_MAIN_SWARM, "y"
	BYTE		OpCode;				// MRC_XXXX
	static int	CheckOpCode(const void* buf);
};

struct MrcCipherPayload
{
	enum Type
	{
		CPLD_CONTENT = 0,
		CPLD_MEDIA_OFFLOADS,
		CPLD_ATTACHMENTS,
		CPLD_OBSERVATORY,			// encrypted by observers
		CPLD_SENDER_ATTACHMENTS,	// encrypted by sender's Secret
		CPLD_TYPE_MAX,

		CPLD_BITMASK = 0xf
	};

	struct Content // CPLD_CONTENT
	{
		uint8_t	Type;
		BYTE	Data[1];
	};

	static const UINT ENCRYPTION_BIT = 0x80;
	static const UINT BLOCKCOUNT_BITMASK = 0x7f;

	BYTE	Payload_Padding;	// [Padding:4bit] + [CipherPayloadType:4bit]
	BYTE	EncBit_BlockCount;	// in multiple of 16 bytes Cipher::DataBlockSize
	BYTE	Data[1];			// BlockCount*16 (encrypted), BlockCount*16 + Padding (unencrypted)

	UINT	GetNonce() const { return Payload_Padding | (EncBit_BlockCount<<8); }
	auto	GetType() const { return (Type)(Payload_Padding&(UINT)CPLD_BITMASK); }
	UINT	GetPaddingSize() const { return Payload_Padding>>4; }
	bool	IsEncrypted() const { return EncBit_BlockCount&ENCRYPTION_BIT; }
	UINT	GetSize() const { return offsetof(MrcCipherPayload, Data) + GetDataSize(); }
	UINT	GetDataSize() const { return (EncBit_BlockCount&BLOCKCOUNT_BITMASK)*Cipher::DataBlockSize + (IsEncrypted()?0:GetPaddingSize()); }
	UINT	GetOriginalDataSize() const { return (EncBit_BlockCount&BLOCKCOUNT_BITMASK)*Cipher::DataBlockSize + (IsEncrypted()?-(int)GetPaddingSize():(int)GetPaddingSize()); }

	template<typename T>
	auto&	Get() const { return *(T*)Data; }
};

enum MrcMessageAttachmentTypes: uint16_t
{
	MRCATT_NONE				= 0,

	MRCATT_TINYGROUP_INFO	= (1U<<0),
	MRCATT_GREETING			= (1U<<1),
	//MRCATT_PROFILE_UPDATED	= (1U<<2),  // deprecated
	//MRCATT_AVATAR_UPDATED	= (1U<<3),		// deprecated
	//MRCATT_OFFLOAD_REFERS	= (1U<<4),		// deprecated
	MRCATT_OFFLOAD_SECRETS	= (1U<<5),
	MRCATT_ACCESS_POINTS	= (1U<<6),

	MRCATT_MAXBITS			= 7
};

struct MrcEnvelope
{
	static const UINT CipherPayloadTypeBits = 12;
	static const UINT CipherPayloadTypeBitmask = 0xfff;

	enum CredentialType
	{
		// The Masterkey is hash(<Nonce> + <payload plaindata 1> + <payload plaindata 2> ...) involves all payloads including unencrypted ones
		EVLP_SEALBOX = 0,	// cred_SealedBox
							// EndPoint should be an ContactUser, Decrypt using ContactUser::SealBox constructed using my-sk and peer-pk, no additional signing required
		EVLP_SEALGREETING,	// cred_SealedGreeting
							// EndPoint should be an SpecialPurpose, Decrypt using ContactUser::SealBox constructed using my-sk and peer-pk
		EVLP_BROADCAST,		// cred_Broadcast, master key is sender's address for follower cast and community secret for community cast
							// EndPoint should be an ContactUser with Broadcast on, AES Decrypt using sender-pk (master key is not used here), or a ContactCommunity
		EVLP_COMMUNITYSEND,	// cred_CommunitySend, master key is community's ContactCommunity::Secret without ContactPoint (broadcast in sub-swarm)
		EVLP_MAXTYPE
	};

	// Memory Layout:  [Header{Time,...,Action}][EncryptionData][MrcCipherPayload x GetPayloadCount()]
	// MrcCipherPayload is encrypted indenpendently
	NetTimestamp	Time;
	uint16_t		Reserved;
	uint16_t		Type_CPLD;		// High 4bit: Envelope Type; Low 12bit: (1<<CipherPayloadType)
	MrcAppId		App;
	uint16_t		Action;			// App specific opcode
	uint8_t			CredentialData[1];
	// [MrcCredential_XXXX]
	// [MrcCipherPayload x GetPayloadCount()]

	template<typename T>
	const T&		GetCredential() const { return *(const T*)&CredentialData[0]; }
	template<typename T>
	T&				GetCredential(){ return *(T*)&CredentialData[0]; }
	UINT			GetCredentialSize() const;

	uint32_t		GetSize() const;

	bool			VerifySize(UINT len) const;
	auto			GetType() const { return (CredentialType)(Type_CPLD>>CipherPayloadTypeBits); }
	void			SetType(CredentialType type){ Type_CPLD = (Type_CPLD&CipherPayloadTypeBitmask) | (type<<CipherPayloadTypeBits);}

	bool			HasPayload(MrcCipherPayload::Type pld) const { return Type_CPLD&(1<<pld); }
	auto			GetPayload(MrcCipherPayload::Type) const -> const MrcCipherPayload*;

	UINT			GetPayloadCount() const { return rt::PopCount(Type_CPLD&CipherPayloadTypeBitmask); }
	auto			GetFirstPayload(uint32_t& iter) const -> const MrcCipherPayload*;
	auto			GetNextPayload(const MrcCipherPayload*, uint32_t& iter) const -> const MrcCipherPayload*;


	bool			HasNonce() const { auto t = GetType(); return t<EVLP_BROADCAST; }
	NonceData&		GetNonce();
	const auto&		GetNonce() const { return rt::_CastToNonconst(this)->GetNonce(); }
	bool			MatchContactPoint(const ext::fast_set<MrcContactPointNum>& cps);
};

struct MrcMessage
{
	static const BYTE PARENT_COUNT_BITMASK = 0x07;

	BYTE			Ver;
	BYTE			Flag;
	uint16_t		TTL = 2; 	// in days
	uint64_t		PowNonce;
	MrcMsgHash		Parents[MRC_PACKETS_PARENT_COUNT];
	// Envelope

	static MrcMessage*	Clone(const MrcMessage& packet);
	static ULONGLONG	PowHashCount(uint16_t msg_size, uint16_t ttl_day, uint16_t pow_factor =1){ return pow_factor*(10ULL*1024 + 10ULL*msg_size*ttl_day); }

	void				SetParentCount(const UINT c) { Flag = (BYTE)c && PARENT_COUNT_BITMASK; }
	UINT				GetParentCount() const { return Flag&PARENT_COUNT_BITMASK; }

	auto&				GetEnvelope() const { return *(MrcEnvelope*)&Parents[GetParentCount()]; }
	UINT				GetSize() const { return offsetof(MrcMessage, Parents) + GetParentCount()*sizeof(MrcMsgHash) + GetEnvelope().GetSize(); }
	int64_t				GetTime() const { return GetEnvelope().Time; }
	int64_t				GetExpirationTime() const { return TTL*24*3600LL*1000LL + GetEnvelope().Time; }
	ULONGLONG			GetPowHashCount() const { return PowHashCount(GetEnvelope().GetSize(), TTL); }

	uint32_t			GetMessageCrc() const;
	MrcMsgHash			GetHashValue() const;

	bool	IsValidSize(int packet_size);
	bool	IsValidPow() const;
	void	Dump(rt::String& out, MrcMsgHash* hash = nullptr) const;
	void	CalcPow();
};

struct MrcMediaOffload
{
	TYPETRAITS_DECLARE_POD;

	GdpHash			Hash;				// hash of encrypted data (Key for MediaRelayCore)
	uint32_t		Size;				// size of encrypted data
	uint32_t		MinuteStamp;		// start time of DTL, unix time in minutes (max: 10141 B.C.)
	uint16_t		DTL;				// TTL in days (typically, it is 1.5 x TTL of DAG message)
	uint8_t			Padding;			// size of padding zeros after the original data for encryption (AES)
	uint8_t			ContentType;
	uint64_t		PowNonce;

	int64_t			ExpirationTime() const { return MinuteStamp*60000LL + DTL*60000LL*60*24; }
	uint32_t		OriginalSize() const { ASSERT(Size>Padding); return Size - Padding; }
};

struct MrcMediaOffloadItem : public MrcMediaOffload
{
	HashValue		SecretHash;			// hash of original media data without padding, also serves as encryption key	
};

struct MrcMediaOffloads
{
	uint8_t			Count;
	MrcMediaOffload	Entries[1];
};

#pragma pack(pop)
} // namespace upw
