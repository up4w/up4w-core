#pragma once
#include "mrc_base.h"


namespace upw
{

struct MrcRecvContext;
struct MrcAttachmentTinyGroupInfo;
class MrcMediaRelayCore;
class MrcMessageDisassembler;
class NetworkServiceCore;

class MrcContactsControl
{
	friend class MessageRelayCore;

	enum ChatsActions
	{
		ACT_TINYGROUP_CREATE = 0x3000,	// a group is created (by group admin only), not a grop message (group admin self-sending), content = osn_address of the group
		ACT_TINYGROUP_MIN = 0x3000,
		ACT_TINYGROUP_ADD,				// add members, content = osn_address_list
		ACT_TINYGROUP_EXPEL,			// remove members, content = osn_address_list
		ACT_TINYGROUP_LEAVE,			// leave the group, no content
		ACT_TINYGROUP_DISMISS,			// dismiss the group (by group admin only), no content
		ACT_TINYGROUP_PROFILE_CHANGE,	// name/location of the group is changed, content = osn_profile_changed
		ACT_TINYGROUP_MAX,
	};

	static const int8_t		GENDER_TINYGROUP = -1;
	static const int16_t	LOCATION_TINYGROUP = 0;
	static const int8_t		SOCIAL_PREFERENCE_TINYGROUP = 0;

protected:
	MrcMediaRelayCore*		_pMediaRelay = nullptr;
	MrcContactsRepository*	_pContacts = nullptr;
	uint64_t				_ContactsRevision = 0;
	void					_10SecondTick(int64_t net_time);
	bool					_CreateTinyGroupInfoFromAdminMessage(MrcMessageDisassembler& msg_dis, const MrcRecvContext& ctx);
	bool					_UpdateTinyGroupInfoFromMessage(MrcMessageDisassembler& msg_disasm, MrcRecvContext& ctx);

	struct CommonContactPoint
	{
		MrcContact	Id;
		MrcContactPoints::SecretType	Secret;
	};
	rt::BufferEx<CommonContactPoint>			_CommonContactPoints;
	os::ThreadSafeMutable<MrcContactPoints>		_ContactPoints;

public:
	bool	HasContracts() const { return _pContacts; }
	auto*	GetContacts() const { return _pContacts; }

	bool	HandleControlMessage(MrcMessageDisassembler& msg, MrcRecvContext& ctx);  // true to continue further processing
	void	ReplaceContact(MrcContact new_id, MrcContact prev_id); // swap contact id with type/relationship/pk unchanged
	void	UpdateContactPoints(int64_t net_time, bool contact_dirty);
	auto	ResolveRecipient(MrcContactPointNum cpid, upw::NetTimestamp tm) { THREADSAFEMUTABLE_SCOPE(_ContactPoints);  return _ContactPoints.GetImmutable().ResolveContact(cpid, tm); }
	auto	GetContactPointCount() const { THREADSAFEMUTABLE_SCOPE(_ContactPoints); return _ContactPoints.GetImmutable().GetCount(); }

	void	AddCommonContactPoint(const MrcContactPoints::SecretType& s, MrcContact id);
	void	ClearCommonContactPoints();
	void	Term();
};

#pragma pack(push, 1)
struct MrcGroupMemberList
{
	uint32_t	Count;
	PublicKey	Members[MRC_MESSAGE_RECIPENTS_MAX - 1];
	uint32_t	GetSize() const { return offsetof(MrcGroupMemberList, Members) + sizeof(PublicKey)*Count; }
};
#pragma pack(pop)

namespace control_msgs
{
#pragma pack(push, 1)

// Group Control Messages
struct MrcTinyGroupMemberList
{
	TYPETRAITS_DECLARE_NON_POD;

	struct Contact
	{
		PublicKey		Member;
		MrcDataKey		PublicData;
	};

	uint8_t				MemberCount;
	Contact				Members[MRC_MESSAGE_RECIPENTS_MAX];  // HasFullContact() = true

	UINT				GetSize() const { return 1 + sizeof(Contact)*MemberCount; }
	bool				Has(const PublicKey& pk) const;
	bool				Compose(MrcContactsRepository* contacts, UINT size_limit, const MrcContact* member, UINT member_count);
};

struct MrcGroupControlSigning
{
	PublicKey			Address;
	MrcContactGroupId	GroupId;
	NetTimestamp		Timestamp;
	BYTE				AdditionData[256];
	UINT				TotalSize;

	MrcGroupControlSigning(const PublicKey& g, const MrcContactGroupId& gid, NetTimestamp time, const rt::String_Ref& addition = nullptr);
	void				Sign(const PrivateKey& sk, SignatureData& out){ sk.Sign(out, this, TotalSize); }
	bool				Verifiy(const PublicKey& pk, const SignatureData& in){ return pk.Verify(in, this, TotalSize); }
};

// osne_chats_action_tinygroup_create
struct MrcTinyGroupActionCreate  // send to creator itself
{
	TYPETRAITS_DECLARE_NON_POD;

	PublicKey				Address;
	MrcContactGroupId		GroupId;
	MrcRootSecretSeed		SecretSeed;
	MrcTinyGroupMemberList	List;	// member not include creator, member list is not sorted
	UINT					GetSize() const { return offsetof(MrcTinyGroupActionCreate, List) + List.GetSize(); }
};

// osne_chats_action_tinygroup_add
struct MrcTinyGroupActionMemberAdd
{
	TYPETRAITS_DECLARE_NON_POD;

	MrcTinyGroupMemberList	List;
	UINT					GetSize() const { return List.GetSize(); }
};

// osne_chats_action_tinygroup_remove
struct MrcTinyGroupActionMemberRemove
{
	TYPETRAITS_DECLARE_NON_POD;

	uint8_t				Count;
	uint8_t				RemovalIndex[MRC_MESSAGE_RECIPENTS_MAX-1];  // Index to MessageAttachmentTinyGroupInfo::Membership
	UINT				GetSize() const { return 1 + Count; }
};

// osne_chats_action_tinygroup_leave
struct MrcTinyGroupActionMemberLeave
{
	SignatureData		LeaveSigned; // sign(GroupAddress + GroupId + Timestamp + Address) by Member
};

// osne_chats_action_tinygroup_dismiss
struct MrcTinyGroupActionDismiss
{
	SignatureData		GroupIdSigned;	// sign(GroupAddress + GroupId + Timestamp + 'dismiss') by Admin
};

#pragma pack(pop)
} // namespace control_msgs
} // namespace upw