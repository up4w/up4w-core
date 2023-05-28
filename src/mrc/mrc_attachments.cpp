#include "mrc_attachments.h"


namespace upw
{

UINT MrcAttachmentTinyGroupInfo::GetSize(LPCBYTE end) const
{
	LPCBYTE p = InfoBlocks;

	if(TGIT_MEMBERSHIP&InfoBlockFlag)
	{
		p += ((Membership*)p)->GetSize();
		if(p>end)return 0;
	}

	if(TGIT_ALL_NAMES&InfoBlockFlag)
	{
		p += ((AllNames*)p)->GetSize();
		if(p>end)return 0;
	}

	return (UINT)(p - (LPCBYTE)this);
}

UINT MrcAttachmentTinyGroupInfo::Compose(MrcContactsRepository* contacts, MrcContact g, const MrcGroupInfo& info, const MrcGroupMember* members, InfoType block_flag)
{
	ASSERT(g && contacts->GetType(g) == MCT_GROUP);

	GroupId = *info.GroupId;

	MrcContactProfile g_profile;
	VERIFY(contacts->GetProfile(g, &g_profile));

	LastModified = contacts->GetLastModified(g);
	Location = g_profile.Location;
	SocialPreference = g_profile.SocialPreference;

	InfoBlockFlag = 0;

	LPBYTE p = InfoBlocks;

	MrcContact mems[MRC_MESSAGE_RECIPENTS_MAX];

	if(TGIT_MEMBERSHIP&block_flag)
	{
		auto& b = *(Membership*)p;
		b.Address = *g_profile.Address;
		b.Count = info.MemberCount;
		b.AdminIndex = info.AdminIndex;
		b.MembershipVersion = info.MembershipVersion;
		for(UINT i=0; i<info.MemberCount; i++)
		{
			auto& bm = b.Members[i];
			bm.Member = *members[i].Member;
			bm.JoinTime = members[i].JoinTime;

			mems[i] = contacts->GetContact(members[i].Member);
			ASSERT(mems[i]);

			MrcContactProfile profile;
			VERIFY(contacts->GetProfile(mems[i], &profile));
			bm.PublicData = *profile.PublicData;
		}

		p += b.GetSize();
		InfoBlockFlag |= TGIT_MEMBERSHIP;
	}

	if((TGIT_ALL_NAMES|TGIT_GROUP_NAME_ONLY)&block_flag)
	{
		ASSERT(TGIT_MEMBERSHIP&block_flag);

		auto& b = *(AllNames*)p;
		LPSTR s = b.Str;

		// group name
		s += 1 + g_profile.Name.CopyToZeroTerminated(s);

		if(TGIT_ALL_NAMES&block_flag)
			for(UINT i=0; i<info.MemberCount; i++)
			{
				MrcContactProfile profile;
				VERIFY(contacts->GetProfile(mems[i], &profile));
				s += 1 + profile.Name.CopyToZeroTerminated(s);
			}

		UINT size = (UINT)(s - b.Str);

		ASSERT(size < 0xffffU);
		b.Len = size;

		p += b.GetSize();
		InfoBlockFlag |= ((TGIT_ALL_NAMES|TGIT_GROUP_NAME_ONLY)&block_flag);
	}

	ASSERT(GetSize() < sizeof(MrcAttachmentTinyGroupInfo));
	return (UINT)(p - (LPBYTE)this);

}

MrcAttachmentTinyGroupInfo::InfoType
MrcAttachmentTinyGroupInfo::DetermineComposeFields(MrcContactsRepository* contacts, MrcContact g, const MrcGroupInfo& info, const MrcGroupMember* members, UINT size_avail)
{
	InfoType type = TGIT_NONE;

	UINT membership_size = sizeof(ContactGroupMember)*info.MemberCount + 1 + sizeof(NetTimestamp);

	MrcContactProfile profile;
	VERIFY(contacts->GetProfile(g, &profile));

	rt::String_Ref name = profile.Name;
	UINT names_size =  name.GetLength() + 1;

	for(UINT i=0; i<info.MemberCount; i++)
	{
		auto m = contacts->GetContact(members[i].Member);
		ASSERT(m);

		VERIFY(contacts->GetProfile(m, &profile));
		if(members[i].Member)names_size += profile.Name.GetLength();
		names_size++;
	}

	names_size += offsetof(AllNames, Str);
				
	if(size_avail >= membership_size)
	{
		((WORD&)type) |= TGIT_MEMBERSHIP;

		if(size_avail >= membership_size + names_size)
			((WORD&)type) |= TGIT_ALL_NAMES;
		else if(size_avail >= membership_size + name.GetLength() + 1 + offsetof(AllNames, Str))
			((WORD&)type) |= TGIT_GROUP_NAME_ONLY;
	}

	return type;
}

bool MrcAttachmentTinyGroupInfo::AllNames::Disassemble(rt::String_Ref* group_name, rt::String_Ref* names, UINT count) const
{
	LPCSTR p = Str;
	LPCSTR end = Str + Len;

	auto sz = strnlen(p, end - p);

	if(group_name)
		*group_name = rt::String_Ref(p, sz);
	p += sz + 1; // skip, first one is group name

	if(p == end)
	{	// only group name
		rt::Zero(names, sizeof(rt::String_Ref)*count);
		return true;
	}

	int i = 0;
	while(p <= end)
	{
		if(i == count)return true;

		sz = strnlen(p, end - p);
		names[i++] = rt::String_Ref(p, sz);

		p += sz + 1;
	}

	return false;
}

} // namespace upw