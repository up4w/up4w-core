#pragma once
#include "../../externs/miniposix/core/rt/type_traits.h"
#include "../secure_identity.h"
#include "../net_types.h"


#define MRC_PROTOCOL_CHAR_MAIN_SWARM	'y'
#define MRC_PROTOCOL_CHAR_EXT_SWARM		'Y'
#define MRC_PACKETS_VERSION				((uint8_t)0x05)
#define MRC_POW_MASK					0xFFFF0000U // little-endian
#define MRC_PACKETS_DB_DURATION			(1000ULL*3600*48)	// 48 Hours
#define MRC_PACKETS_MEM_DURATION		(1000ULL*3600*2)	// 2  Hours
#define MRC_PACKETS_MAX_TIMESHIFT		(1000ULL*60)		// 1 Minute
#define MRC_CONTACTPOINTS_DURATION		(1000ULL*60*10)		// 10 Minutes
#define MRC_STATUS_PING_INTERVAL		5000
#define MRC_STATUS_PING_MAX_COUNT		127
#define MRC_PACKETS_PARENT_COUNT		4
#define MRC_SWARM_SIZE					6U
#define MRC_CONTACTPOINT_SHIFT			(15 + 5)
#define MRC_TIMESTAMP_UNIT				(1LL<<SOCIAL_TIMESTAMP_UNIT_SHIFT)	// 64 msec
#define MRC_MESSAGE_CONTENT_MAXSIZE		2000U		// TBD ...
#define MRC_MESSAGE_MTU					1200U
#define MRC_MESSAGE_RECIPENTS_MAX		10
#define MRC_CONTACTPOINT_SUBBAND_BITS	0x3U		// must be 2^n - 1
#define MRC_PROFILE_NAME_SIZEMAX		64
#define MRC_CONTENT_TYPE_UTF8			13
#define MRC_CONTENT_TYPE_UTF16			14
#define MRC_CONTACTPOINT_INTERVAL		(1LL<<(NET_TIMESTAMP_UNIT_SHIFT + MRC_CONTACTPOINT_SHIFT)) // 17 min * 2^5
#define MRC_CONTACTPOINT_DURATION_MAX	(48LL*3600*1000)	// 48 hours

#if !defined(MRC_PARALLEL_SWARM_COUNT)
#define MRC_PARALLEL_SWARM_COUNT		16 // common peer
#endif

#define MRC_MEDIA_BLOB_PAGESIZE			(256U*1024U)		// same with GDP
#define MRC_MEDIA_BLOB_MAXSIZE			(128ULL*1024*1024)  // 128MB
#define MRC_MEDIA_MISSING_CACHE_SIZE	10000U
#define MRC_HIDDENBYTES_MASKSIZE		256U*1024U		// 256kb

namespace upw
{
struct DhtAddress;

#pragma pack(push, 1)

typedef uint64_t			MrcMsgHash;
inline uint32_t				MrcMsgHashToMsgCrc(MrcMsgHash hash){ return (uint32_t)hash; }

typedef size_t				MrcContact;

typedef uint64_t			MrcContactPointNum;
static const				MrcContactPointNum	MrcContactPointZero = 0ULL;
static const				MrcContactPointNum	MrcContactPointVoid = 0xffffffffffffffffULL;

typedef uint16_t			MrcAppId; // TODO: should change to uint32_t later
static const				MrcAppId MrcAppSystem = 0;
static const				MrcAppId MrcAppChats = 1;

typedef sec::DataBlock<16>	MrcContactGroupId;

struct MrcDataKey: public PublicKey
{
	MrcDataKey() = default;
	MrcDataKey(const MrcDataKey& pk) = default;
	MrcDataKey(const PublicKey& pk):PublicKey(pk){}

	bool	IsValid() const { return Bytes[31] == 0; }
};

class MrcKeyPair
{
	TYPETRAITS_DECLARE_POD;
	ED_PrivateKey       _Private;
public:
	auto&		Public() const { return _Private.GetPublicKey(); }
	auto&		DataKey() const { auto& r = (MrcDataKey&)Public(); ASSERT(r.IsValid()); return r; }
	auto&		Private() const { return _Private; }
	void		Generate(const ED_Seed& Seed){	ED_PublicKey pk; crypto_sign_ed25519_seed_keypair(pk, _Private, Seed); }
	void		Generate(){	ED_Seed seed; sec::Randomize(seed); Generate(seed); }

	MrcKeyPair() = default;
	MrcKeyPair(const MrcKeyPair&x):_Private(x._Private){}
	MrcKeyPair(const ED_PublicKey& pk, const ED_PrivateKey& sk):_Private(sk){ ASSERT(Public() == pk); }
	const MrcKeyPair& operator = (const MrcKeyPair& x){ _Private = x._Private; return x; }
	operator const PublicKey&() const { return _Private.GetPublicKey(); }
	operator const PrivateKey&() const { return _Private; }

	template<typename OStream>
	friend OStream& operator <<(OStream& s, const MrcKeyPair& d){ return s << '[' << d.Public() << ']' << '/' << '[' << d.Private() << ']';	}
};

struct MrcRootSecretSeed: public sec::DataBlock<28, true>
{
	TYPETRAITS_DECLARE_NON_POD;
	static const int EffectiveLength = 27;

	void		Random(){ sec::Randomize(*this); Bytes[EffectiveLength] = 0; }
	void		DeriveDataKeypair(const rt::String_Ref& name, MrcKeyPair& out) const;
	void		DeriveSocialIdKeypair(MrcKeyPair& out) const;
	void		DerivePublicDataKeyPair(MrcKeyPair& out) const { DeriveDataKeypair("PublicData", out); }
	void		DerivePrivateDataKeyPair(MrcKeyPair& out) const { DeriveDataKeypair("PrivateInfo", out); }

private:
	UINT		GetLength() const { ASSERT(0); return 0; }
};

#pragma pack(pop)

namespace _details
{
	extern LPCBYTE			__HiddenBytesMaskBytes;
	extern const UINT		__HiddenBytesMaskSize;
} // namespace _details

template<typename T>
class HiddenBytes
{
    static_assert(((sizeof(T)%sizeof(DWORD)) == 0), "HiddenBytes only hosts a type whose size is multiplication of 4-byte");
	DWORD	_Bytes[sizeof(T)/sizeof(DWORD)];
	UINT	_MaskOffset;
public:
	~HiddenBytes(){ rt::Zero(*this); }
	HiddenBytes(){ _MaskOffset = INFINITE; }
	HiddenBytes(const T& s){ Hide(s); }
	HiddenBytes(const HiddenBytes& x){ *this = x; }
	void operator = (const T& x){ Hide(x); }
	void operator = (const HiddenBytes& x){ T s; x.Reveal(s); Hide(s); }

	void Hide(const T& x)
	{	_MaskOffset = 4*((((SIZE_T)this)^os::Timestamp::Get())%((_details::__HiddenBytesMaskSize - sizeof(T))/4));
		LPDWORD p = _Bytes;
		LPCDWORD s = (LPCDWORD)&x;
		LPCDWORD m = (LPCDWORD)(_details::__HiddenBytesMaskBytes+_MaskOffset);
		for(SIZE_T i=0;i<sizeof(T)/sizeof(DWORD);i++)
			p[i] = s[i] ^ m[i];
	}
	void Reveal(T& x) const
	{	ASSERT(!IsEmpty());
		LPCDWORD p = _Bytes;
		LPDWORD d = (LPDWORD)&x;
		LPCDWORD m = (LPCDWORD)(_details::__HiddenBytesMaskBytes+_MaskOffset);
		for(SIZE_T i=0;i<sizeof(T)/sizeof(DWORD);i++)
			d[i] = p[i] ^ m[i];
	}
	T	 Reveal() const { T _; Reveal(_); return _; }
	void Empty(){ rt::Zero(_Bytes); _MaskOffset = INFINITE; }
	bool IsEmpty() const { return _MaskOffset == INFINITE; }
};

/////////////////////////////////////////////////////////////////
// Hashrate with a single thread
// PC: 400k hash/sec
// iPhone: 960k hash/sec
class MrcPowDifficulty
{
	TYPETRAITS_UNITTEST_OPEN_ACCESS;
	static const int HASHSIZE = 32;
	UINT		_TargetNum;
	int			_NonZeroBytes;
public:
	MrcPowDifficulty(UINT expected_hash_count){ Set(expected_hash_count); }
	MrcPowDifficulty(ULONGLONG expected_hash_count){ Set(expected_hash_count); }
	void		Set(UINT expected_hash_count, UINT e2_shift = 0);
	void		Set(ULONGLONG expected_hash_count);
	bool		IsFulfilled(LPCVOID hashval) const; // pointing to HASHSIZE bytes

	bool		IsFulfilled(BYTE data[64], uint64_t nonce) const; // data will be modified
	uint64_t	SearchNonce(BYTE data[64], uint64_t nonce_init = 0) const;  // data will be modified
};

inline LONGLONG	GetTimeFromEpoch(DWORD epoch){ return ((ULONGLONG)epoch)<<(NET_TIMESTAMP_UNIT_SHIFT + MRC_CONTACTPOINT_SHIFT); }
inline DWORD	GetEpochForContactPoint(const NetTimestamp& t){ return (DWORD)(((*(ULONGLONG*)&t)&NetTimestamp::Max)>>MRC_CONTACTPOINT_SHIFT); }
extern auto		GetContactPointByEpoch(LPCVOID secret, UINT secret_size, DWORD epoch) -> MrcContactPointNum;
inline auto		GetContactPoint(const NetTimestamp& time, LPCVOID secret, UINT secret_size){ return GetContactPointByEpoch(secret, secret_size, GetEpochForContactPoint(time)); }
extern auto		GetContactPointByEpochWithSubband(LPCVOID secret, UINT secret_size, DWORD epoch, uint32_t subband) -> MrcContactPointNum;
inline auto		GetContactPointWithSubband(const NetTimestamp& time, uint32_t subband, LPCVOID secret, UINT secret_size){ return GetContactPointByEpochWithSubband(secret, secret_size, GetEpochForContactPoint(time), subband); }

struct MrcRecvContext
{
	enum SourceType
	{
		SourceNetwork = 0,		// recv-ed from remote node via network
		SourceReplaySignin,		// message playback from local storage (when user login)
		SourceReplayRequest,	// message playback from local storage (at requested)
		SourceLoopback,			// message sent by local node
	};

	MrcMsgHash			MsgHash;
	SourceType			Source;
	const DhtAddress*	SwarmAddr = nullptr;
	MrcContact			Conversation = 0;

	MrcRecvContext(MrcMsgHash hash, SourceType s, const DhtAddress* swarm = 0, MrcContact conv = 0);
};

struct MrcWorkload
{
	int64_t TotalCount = 0;
	int64_t UnreferredCount = 0;
	int64_t MissingCount = 0;
};

struct MrcMediaWorkload
{
	int64_t TotalCount = 0;
	int64_t TotalBytes = 0;
	int64_t MissingCount = 0;
	int64_t MissingBytes = 0;
	int64_t AvailableCount = 0;
	int64_t AvailableBytes = 0;
};

struct MrcContactsRepository;

class MrcContactPoints
{
	static_assert(sizeof(CipherSecret) == 32);
	static const int SECRET_PERCONTACT_MAX = 4;
public:
	typedef sec::DataBlock<32>	SecretType;
	typedef const void*			SecretTypePtr;
protected:
#if defined(PLATFORM_DEBUG_BUILD)
	struct ContactPointMapValue
	{
		MrcContact			Id;
		SecretType			Secret;
		DWORD				Epoch;
		UINT				Subband;

		operator MrcContact() const { return Id; }
		void operator = (MrcContact id){ Id = id; }
	};
#else
	typedef MrcContact		ContactPointMapValue;
#endif

	struct ContactPointMap: public ext::fast_map<MrcContactPointNum, ContactPointMapValue>
	{
		void AddContact(DWORD epoch, MrcContact id, const SecretType** secrets, uint32_t secret_count);
		void ReplaceContact(DWORD epoch, MrcContact id, const SecretType** secrets, uint32_t secret_count, MrcContact prev_id);
	};

	static const UINT FullContactPointMapsPreSlot = 1;
	static const UINT FullContactPointMapsLength = MRC_CONTACTPOINT_DURATION_MAX/MRC_CONTACTPOINT_INTERVAL + FullContactPointMapsPreSlot;

protected:
	mutable bool			_MapWasTaken = false;
	DWORD					_BaseEpoch;
	ContactPointMap*		_Maps[FullContactPointMapsLength];

	ContactPointMap*		_CreateContactPointMap(MrcContactsRepository* contacts, DWORD epoch) const;
	ContactPointMap*		_Set(DWORD epoch, ContactPointMap* new_map);
	static uint32_t			_GetContactPointSecrets(MrcContactsRepository* contacts, MrcContact id, SecretTypePtr secret_out[SECRET_PERCONTACT_MAX]);

public:
	MrcContactPoints(){ rt::Zero(*this); }
	~MrcContactPoints();
	void					MarkMapTaken() const { _MapWasTaken = true; }

	const ContactPointMap*	Get(const NetTimestamp& tm) const { return Get(GetEpochForContactPoint(tm)); }
	const ContactPointMap*	Get(DWORD epoch) const { if(epoch>=_BaseEpoch && epoch-_BaseEpoch<sizeofArray(_Maps)){ return _Maps[epoch-_BaseEpoch]; }else{ return nullptr; } }
	void					ReplaceContact(MrcContactsRepository* contacts, MrcContact new_id, MrcContact prev_id);

	int						EpochToIndex(DWORD epoch) const { if(epoch>=_BaseEpoch && epoch-_BaseEpoch<sizeofArray(_Maps)){ return epoch-_BaseEpoch; }else{ return -1; } }
	DWORD					GetMaxEpoch() const { return _BaseEpoch + FullContactPointMapsLength - 1; }
	UINT					GetCount() const { return _Maps[0]?(UINT)_Maps[0]->size():0U; }
	void					Update(MrcContactsRepository* contacts, int64_t time, bool contact_dirty);
	bool					IsEpochShifting(int64_t net_time) const;
	void					AddContactPoint(const MrcContactPoints::SecretType& s, MrcContact id);

	MrcContact				ResolveContact(MrcContactPointNum x, const NetTimestamp& tm) const
							{	auto* m = Get(tm);
								if(m)
								{	auto it = m->find(x);
									if(it != m->end())
										return it->second;
								}
								return 0;
							}
};

//////////////////////////////////////////////////////
// MrcContactsRepository Interface
enum MrcContactType
{
	MCT_INVALID = -1,
	MCT_USER_GREETING,  // contact point that accepts greeting from anonymous people
	MCT_USER = 0x10,
	MCT_CONVERSATION = MCT_USER,
	MCT_GROUP,
	MCT_COMMUNITY
};

enum MrcContactRelationship
{
	MCR_NONE			= 0x000,
	// with User
	MCR_FRIENDED		= (1<<0),
	MCR_FOLLOWED		= (1<<1),
	MCR_COJOIN			= (1<<2),	// co-join in at least one group
	MCR_BLOCKED			= (1<<6),
	MCR_DELETED			= (1<<7),
	MCR_ENGAGED			= MCR_FRIENDED | MCR_COJOIN,
	MCR_KNOWN			= MCR_FRIENDED | MCR_COJOIN | MCR_FOLLOWED,
	// with Group
	MCR_GROUP_MEMBER	= 0x100,
	MCR_GROUP_OWNER		= 0x200,
	MCR_GROUP_DISMISSED = 0x300,
	MCR_GROUP_LEFT		= 0x400,
	MCR_GROUP_EXPELLED	= 0x500,
	MCR_GROUP_DELETED	= 0x600,
	MCR_GROUP_BITMASK	= 0x700,
};

enum MrcContactPreference
{
	MSP_NONE			= 0,
	MSP_FOLLOWER_CAST	= 1<<0, // the peer will use cast-to-all-followers
	MSP_PROACTIVE_PUSH	= 1<<1, // the peer accepts proactive message notification
	MSP_OPEN_FRIENDING	= 1<<3, // the peer accepts friend request from anonymous in the community (must be 1<<3)

	MSP_LOCAL_MUTE			 = 0x100<<0,	// conversation don't show up, new message received and archived immediately 
	MSP_LOCAL_SILENT		 = 0x100<<1,	// conversation sends no notification of new message
	MSP_LOCAL_TRUSTED		 = 0x100<<2,	// will expose AccessPoints to receipient
	MSP_LOCAL_OPEN_FRIENDING = 0x100<<3,	// will accept friend request from anonymous in the community
};

struct MrcContactProfile
{
	rt::String_Ref		Name;			// nullptr will have no change in SetProfile
	const PublicKey*	Address;		// ignored in SetProfile
	const MrcDataKey*	PublicData;		// nullptr will have no change in SetProfile
	uint8_t				SocialPreference;
	uint8_t				Gender;
	uint16_t			Location;
};

struct MrcGroupMember
{
	const PublicKey*	Member;
	NetTimestamp		JoinTime;
};

struct MrcGroupInfo
{
	BYTE						MemberCount;
	BYTE						AdminIndex;
	WORD						MembershipVersion;
	const MrcContactGroupId*	GroupId;	// nullptr will have no change in SetGroupMembership
};

struct MrcContactIterator
{
	virtual bool				OnContact(MrcContact c) = 0;  // return false to stop
};

struct MrcContactsRepository
{
	// for current sign-in user
	virtual void					GetNonce(NonceData* nonce_out) = 0;
	virtual void					SignOnBehalfOfMe(SignatureData* sig_out, const void* data, uint32_t data_size) = 0;
	virtual bool					DecryptAnonymousDataToMe(const void* data, uint32_t data_size, void* plain_out) = 0;
	virtual bool					IsMyself(MrcContact contact) = 0;
	virtual MrcContact				GetMyself() = 0;
	virtual bool					SetMyself(const MrcRootSecretSeed* seed, const MrcContactProfile* my) = 0;

	// contacts basic info, accepts MrcContactMySelf
	virtual MrcContactType			GetType(MrcContact contact) = 0;
	virtual MrcContactRelationship	GetRelationship(MrcContact contact) = 0;
	virtual MrcContactPreference	GetSocialPreference(MrcContact contact) = 0;
	virtual MrcContact				GetContact(const PublicKey* pk) = 0;
	virtual const PublicKey*		GetPublicKey(MrcContact contact) = 0;
	virtual int64_t					GetLastModified(MrcContact contact) = 0; // modification of social metadata
	virtual bool					GetProfile(MrcContact contact, MrcContactProfile* out) = 0;
	virtual uint32_t				ScanContacts(MrcContactIterator * it, int64_t time) = 0; // # of calls before end/stop

	// contacts secure communication
	virtual const CipherSecret*		GetSecret(MrcContact contact) = 0; // MutualSecret for MCT_USER, CipherSecret for MCT_COMMUNITY
	virtual const CipherSecret*		GetUserGreetingSecret(MrcContact contact) = 0; // MutualSecret for MCT_USER (AdhocMutual)
	virtual bool					EncryptKeyToUser(MrcContact recipent, const NonceData* nonce, const CipherSecret* plain_key, SealedCipherSecret* encrypted_key_out) = 0;
	virtual bool					DecryptKeyFromUser(MrcContact sender, const NonceData* nonce, const SealedCipherSecret* encrypted_key, CipherSecret* plain_key_out) = 0;
	virtual bool					VerifySignature(MrcContact contact, const void* data, uint32_t data_size, const SignatureData* sig) = 0;

	// contact modification
	virtual MrcContact				CreateUser(const MrcContactProfile* profile, bool by_greeting, const upw::CipherSecret* greeting_secret = nullptr) = 0;
	virtual void					RemoveContact(MrcContact contact) = 0;
	virtual MrcContact				SetProfile(MrcContact contact, const MrcContactProfile* in, NetTimestamp modified_time) = 0; // after SetProfile the contact handle might be swapped
	virtual MrcContactRelationship	SetRelationship(MrcContact contact, MrcContactRelationship new_relation) = 0; // return old relationship

	// for contact group only (tinygroup)
	virtual MrcContact				GetGroup(const MrcContactGroupId* id) = 0;
	virtual bool					GetGroupInfo(MrcContact group, MrcGroupInfo* out) = 0;
	virtual uint32_t				GetGroupMembers(MrcContact group, MrcGroupMember* members, uint32_t member_count) = 0;
	virtual int						GetGroupMemberIndex(MrcContact group, const PublicKey* user) = 0;

	// group modification
	virtual MrcContact				CreateGroup(const MrcContactProfile* group, const MrcGroupInfo* info, const PublicKey*const* members, const MrcDataKey*const* public_data, NetTimestamp modified_time, const MrcRootSecretSeed* pAdminSecret) = 0; // contacts of all members will be auto-created as well as cojoin if not existed, no need to call SetGroupCoJoinContacts for initial members
	virtual MrcContact				SetGroupMembership(MrcContact group, const MrcGroupInfo* info, const MrcGroupMember* members, NetTimestamp time) = 0; // after SetGroupMembership the contact handle might be swapped
	virtual bool					SetGroupCoJoinContacts(MrcContact group, const MrcGroupMember* users, const MrcDataKey*const* public_data, const rt::String_Ref* names, uint32_t count) = 0;
	virtual void					UnsetGroupCoJoinContacts(MrcContact group, const MrcContact* users, uint32_t count) = 0;

	virtual void					Release() = 0;
	virtual uint64_t				GetRepositoryRevisionNumber() = 0;
};

extern void MrcIdenticon(DWORD crc, rt::String& image_data, int background_brightness);

} // namespace upw
