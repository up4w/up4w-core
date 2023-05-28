#pragma once
#include "mrc_message.h"


namespace upw
{
#pragma pack(push, 1)

struct MrcAttachmentGreeting
{
	TYPETRAITS_DECLARE_NON_POD;

	PublicKey			Sender;
	BYTE				Size;			// size of the entire structure
	MrcDataKey			PublicData;		// user public data key
	BYTE				SocialPreference;		// osn_social_flag (low 8-bits)
	// ProfileIntro
	int8_t				Gender;
	int16_t				Location;		// don't adding member above here (osn_greeting_bylink depending on that)
	char				NameBuf[MRC_PROFILE_NAME_SIZEMAX];

	void				SetSizeWithoutIntro(){ Size = (BYTE)(offsetof(MrcAttachmentGreeting, Gender)); }
	void				SetSizeWithIntro(UINT name_len){ Size = (BYTE)(offsetof(MrcAttachmentGreeting, NameBuf) + name_len); }
	UINT				GetSize() const { return Size; }
	bool				HasProfileIntro() const { return Size > offsetof(MrcAttachmentGreeting, Gender); }
	rt::String_Ref		GetName() const { ASSERT(HasProfileIntro()); return rt::String_Ref(NameBuf, Size - offsetof(MrcAttachmentGreeting, NameBuf)); }
};

struct MrcAttachmentAccessPoints
{
	TYPETRAITS_DECLARE_NON_POD;

	DhtAddress			DeviceId;
	NodeAccessPoints	APS;	// BYTE[APS_ReservedSize]
	UINT				GetSize() const { return offsetof(MrcAttachmentAccessPoints, APS) + APS.GetSize(); }
};

struct MrcAttachmentMediaOffloadSecrets
{
	TYPETRAITS_DECLARE_NON_POD;

	BYTE				Count;
	HashValue			Secrets[1];
	UINT				GetSize() const { return offsetof(MrcAttachmentMediaOffloadSecrets, Secrets) + Count*sizeof(HashValue); }
};

struct MrcAttachmentTinyGroupInfo // MSGATT_TINYGROUP_INFO
{
	TYPETRAITS_DECLARE_NON_POD;

	enum InfoType : WORD
	{
		TGIT_NONE				= 0,
		TGIT_MEMBERSHIP			= (1U<<0),
		TGIT_ALL_NAMES			= (1U<<1),
		TGIT_GROUP_NAME_ONLY	= (1U<<2),
	};

	struct ContactGroupMember
	{
		PublicKey		Member;
		NetTimestamp	JoinTime;
		bool operator < (const ContactGroupMember& x) const { return Member < x.Member; }
	};

	MrcContactGroupId	GroupId;		// = ContactGroup::GroupId
	NetTimestamp		LastModified;
	uint16_t			Location;
	BYTE				SocialPreference;		// osne_social_contact_bitmask & Info.flag

	WORD				InfoBlockFlag;	// TinyGroupInfoType bit-combind
	BYTE				InfoBlocks[1 + 4 + (1+MRC_PROFILE_NAME_SIZEMAX+sizeof(ContactGroupMember))*MRC_MESSAGE_RECIPENTS_MAX];

	struct AllNames // TGIT_ALL_NAMES
	{	
		WORD	Len;
		char	Str[1];	// '\x0' separated strings, first is group name, followed by member names
		UINT	GetSize() const { return Len + sizeof(Len); }

		auto	GetGroupName() const { return rt::String_Ref(Str, Len).GetLengthRecalculated(); }
		bool	Disassemble(rt::String_Ref* group_name, rt::String_Ref* member_names, UINT member_count) const;
	};

	struct FullMember
	{
		PublicKey		Member;
		MrcDataKey		PublicData;
		NetTimestamp	JoinTime;
	};

	struct Membership // TGIT_MEMBERSHIP
	{
		PublicKey		Address;
		WORD			MembershipVersion;
		BYTE			AdminIndex; // refers to Members
		BYTE			Count;
		FullMember		Members[1];
		UINT			GetSize() const { return sizeof(FullMember)*Count + offsetof(Membership, Members); }
		bool			IsValid() const { return Count > AdminIndex && Count <= MRC_MESSAGE_RECIPENTS_MAX; }
	};

	UINT	GetSize(LPCBYTE end = (LPCBYTE)(SIZE_T)-1) const; // return 0 if failed
	UINT	Compose(MrcContactsRepository* contacts, MrcContact g, const MrcGroupInfo& info, const MrcGroupMember* members, InfoType block_flag = TGIT_NONE); // return GetSize()

	bool	HasMembership() const { return InfoBlockFlag&TGIT_MEMBERSHIP; }
	bool	HasAllNames() const { return (InfoBlockFlag&(TGIT_ALL_NAMES|TGIT_MEMBERSHIP)) == (TGIT_ALL_NAMES|TGIT_MEMBERSHIP); }
	bool	HasGroupName() const { return InfoBlockFlag&(TGIT_ALL_NAMES|TGIT_GROUP_NAME_ONLY); }

	auto&	GetMembership() const { ASSERT(HasMembership()); return *(const Membership*)InfoBlocks; }
	auto&	GetAllNames() const { ASSERT(HasAllNames()); return *(const AllNames*)&InfoBlocks[GetMembership().GetSize()]; }  // (Membership::Count + 1) strings, first one is group name
	auto	GetGroupName() const { ASSERT(HasGroupName()); return ((const AllNames*)&InfoBlocks[GetMembership().GetSize()])->GetGroupName(); }

	static	auto DetermineComposeFields(MrcContactsRepository* contacts, MrcContact g, const MrcGroupInfo& info, const MrcGroupMember* members, UINT size_avail) -> InfoType;
};

#pragma pack(pop)
} // namespace upw