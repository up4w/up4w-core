#pragma once
#include "mrc_base.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"


namespace upw
{
class MessageRelayCore;

class MrcContacts: public MrcContactsRepository
{
	struct Contact
	{
		MrcContactType			Type;
		MutualSecret			Secret;
		LONGLONG				LastModified;
	};

	struct ContactConversion: public Contact
	{
		PublicKey				Address;
		MrcContactRelationship	Relationship;
		uint8_t					Gender;
		uint16_t				Location;
		uint16_t				SocialPreference;
		rt::BufferFx<char, MRC_PROFILE_NAME_SIZEMAX> Name;
	};

	struct User: public ContactConversion
	{
		MrcDataKey				PublicData;
		CipherSecret			GreetingSecret;
		Cryptography			SealBox;
	};

	struct Group: public ContactConversion
	{
		struct Member
		{
			PublicKey			Address;
			NetTimestamp		JoinTime;
		};

		MrcContactGroupId		GroupId;	// also determines DHT address for subspace swarm (never change)
		WORD					MembershipVersion;
		BYTE					AdminIndex;
		BYTE					MemberCount;
		Member					Members[MRC_MESSAGE_RECIPENTS_MAX];

		HiddenBytes<MrcRootSecretSeed>	RootSeed;
		HiddenBytes<PrivateKey>			SocialIdSK; // for signing
	};

	MessageRelayCore&				_Core;
	volatile int64_t				_Revision;

	typedef ext::fast_map_ptr<PublicKey, Contact, rt::_details::hash_compare_fix<PublicKey>> t_ContactMap;
	typedef ext::fast_map_ptr<MrcContactGroupId, Group, rt::_details::hash_compare_fix<MrcContactGroupId>> t_GroupMap;
	os::CriticalSection				_CS;
	t_ContactMap					_Contacts;
	t_GroupMap						_Groups;

	os::CriticalSection				_MyCS;
	User							_Myself;
	HiddenBytes<MrcRootSecretSeed>	_MyRootSeed;
	HiddenBytes<PrivateKey>			_MySocialIdSK;
	PublicEncryptor					_MySocialIdEncrypt;
	PrivateDecryptor				_MySocialIdDecrypt;

	void							_RemoveAllContacts();
	void							_UpdateContactPoints();
	void							_CopyProfile(const MrcContactProfile* profile, ContactConversion* c) const;
	void							_CopyProfileName(const rt::String_Ref& name, ContactConversion* c) const;
	void							_SetupUserSecurity(User* u) const;
	template<typename T>
	T*								_Create() const { auto* r = _Malloc8AL(T, 1); rt::Zero(*r); return r; }

protected:
	// for current sign-in user
	virtual void					GetNonce(NonceData* nonce_out) override;
	virtual void					SignOnBehalfOfMe(SignatureData* sig_out, const void* data, uint32_t data_size) override;
	virtual bool					DecryptAnonymousDataToMe(const void* data, uint32_t data_size, void* plain_out) override;
	virtual bool					IsMyself(MrcContact contact) override;
	virtual MrcContact				GetMyself() override;
	virtual bool					SetMyself(const MrcRootSecretSeed* seed, const MrcContactProfile* my) override;

	// contacts basic info, accepts MrcContactMySelf
	virtual MrcContactType			GetType(MrcContact contact) override;
	virtual MrcContactRelationship	GetRelationship(MrcContact contact) override;
	virtual MrcContactPreference	GetSocialPreference(MrcContact contact) override;
	virtual MrcContact				GetContact(const PublicKey* pk) override;
	virtual const PublicKey*		GetPublicKey(MrcContact contact) override;
	virtual int64_t					GetLastModified(MrcContact contact) override; // modification of social metadata
	virtual bool					GetProfile(MrcContact contact, MrcContactProfile* out) override;
	virtual uint32_t				ScanContacts(MrcContactIterator * it, int64_t time) override; // # of calls before end/stop

	// contacts secure communication
	virtual const CipherSecret*		GetSecret(MrcContact contact) override; // MutualSecret for MCT_USER, CipherSecret for MCT_COMMUNITY
	virtual const CipherSecret*		GetUserGreetingSecret(MrcContact contact) override; // MutualSecret for MCT_USER (AdhocMutual)
	virtual bool					EncryptKeyToUser(MrcContact recipent, const NonceData* nonce, const CipherSecret* plain_key, SealedCipherSecret* encrypted_key_out) override;
	virtual bool					DecryptKeyFromUser(MrcContact sender, const NonceData* nonce, const SealedCipherSecret* encrypted_key, CipherSecret* plain_key_out) override;
	virtual bool					VerifySignature(MrcContact contact, const void* data, uint32_t data_size, const SignatureData* sig) override;

	// contact modification
	virtual MrcContact				CreateUser(const MrcContactProfile* profile, bool by_greeting, const upw::CipherSecret* greeting_secret = nullptr) override;
	virtual void					RemoveContact(MrcContact contact) override;
	virtual MrcContact				SetProfile(MrcContact contact, const MrcContactProfile* in, NetTimestamp modified_time) override; // after SetProfile the contact handle might be swapped
	virtual MrcContactRelationship	SetRelationship(MrcContact contact, MrcContactRelationship new_relation) override; // return old relationship

	// for contact group only (tinygroup)
	virtual MrcContact				GetGroup(const MrcContactGroupId* id) override;
	virtual bool					GetGroupInfo(MrcContact group, MrcGroupInfo* out) override;
	virtual uint32_t				GetGroupMembers(MrcContact group, MrcGroupMember* members, uint32_t member_count) override;
	virtual int						GetGroupMemberIndex(MrcContact group, const PublicKey* user) override;

	// group modification
	virtual MrcContact				CreateGroup(const MrcContactProfile* group, const MrcGroupInfo* info, const PublicKey*const* members, const MrcDataKey*const* public_data, NetTimestamp modified_time, const MrcRootSecretSeed* pAdminSecret) override; // contacts of all members will be auto-created as well as cojoin if not existed, no need to call SetGroupCoJoinContacts for initial members
	virtual MrcContact				SetGroupMembership(MrcContact group, const MrcGroupInfo* info, const MrcGroupMember* members, NetTimestamp time) override; // after SetGroupMembership the contact handle might be swapped
	virtual bool					SetGroupCoJoinContacts(MrcContact group, const MrcGroupMember* users, const MrcDataKey*const* public_data, const rt::String_Ref* names, uint32_t count) override;
	virtual void					UnsetGroupCoJoinContacts(MrcContact group, const MrcContact* users, uint32_t count) override;

	// object
	virtual void					Release() override { _SafeDel_ConstPtr(this); }
	virtual uint64_t				GetRepositoryRevisionNumber() override { return _Revision; }

public:
	MrcContacts(MessageRelayCore& c);
};

} // namespace upw