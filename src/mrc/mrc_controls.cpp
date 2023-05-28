#include "mrc.h"
#include "mrc_dissemble.h"
#include "mrc_attachments.h"
#include "mrc_controls.h"
#include "mrc_media_core.h"


namespace upw
{

using namespace control_msgs;

void MrcContactsControl::Term()
{
	ClearCommonContactPoints();
	_ContactPoints.Clear();
	_pMediaRelay = nullptr;
}

void MrcContactsControl::ReplaceContact(MrcContact new_id, MrcContact prev_id)
{
	ASSERT(_pContacts);
	ASSERT(_pContacts->GetType(new_id) == _pContacts->GetType(prev_id));
	ASSERT(_pContacts->GetRelationship(new_id) == _pContacts->GetRelationship(prev_id));
	ASSERT(*_pContacts->GetPublicKey(new_id) == *_pContacts->GetPublicKey(prev_id));

	THREADSAFEMUTABLE_LOCK(_ContactPoints);
	_ContactPoints.GetUnsafeMutable().ReplaceContact(_pContacts, new_id, prev_id);
}

void MrcContactsControl::AddCommonContactPoint(const MrcContactPoints::SecretType& s, MrcContact id)
{
	_CommonContactPoints.push_back({id,s});
}

void MrcContactsControl::ClearCommonContactPoints()
{
	_CommonContactPoints.ShrinkSize(0);
}

void MrcContactsControl::_10SecondTick(int64_t net_time)
{
	if(_pContacts && _pContacts->GetMyself())
	{
		uint64_t last = _pContacts->GetRepositoryRevisionNumber();
		UpdateContactPoints(net_time, last > _ContactsRevision);
	}
}

void MrcContactsControl::UpdateContactPoints(int64_t net_time, bool contact_dirty)
{
	_ContactsRevision = _pContacts->GetRepositoryRevisionNumber();

	if(!contact_dirty)
	{
		THREADSAFEMUTABLE_SCOPE(_ContactPoints);
		if(!_ContactPoints.GetImmutable().IsEpochShifting(net_time))
			return;
	}

	THREADSAFEMUTABLE_UPDATE(_ContactPoints, cps);
	cps->Update(_pContacts, net_time, contact_dirty);
	for(auto& it : _CommonContactPoints)
		cps->AddContactPoint(it.Secret, it.Id);

	cps.GetUnmodified().MarkMapTaken();
}

bool MrcContactsControl::HandleControlMessage(MrcMessageDisassembler& msg, MrcRecvContext& ctx)
{
	auto& env = *msg._pEnvelope;
	ASSERT(msg.IsMasterKeyDecrypted());
	
	// tiny group control
	if(msg.IsGroupMessage())
	{
		ASSERT(msg._GroupContact == 0);
		ASSERT(msg._PeerMain);
		if(!msg._pTinyGroupInfo)return false;

		if(!_UpdateTinyGroupInfoFromMessage(msg, ctx))
			return false;
	}
	else if(msg.IsSentByMe())
	{
		if(	env.Action == ACT_TINYGROUP_CREATE &&
			env.App == MrcAppChats
		)
		{
			if(!_CreateTinyGroupInfoFromAdminMessage(msg, ctx))
				return false;
		}
	}
	
	// handle greeting
	if(msg.IsSentByOtherUser())
	{
		auto r = _pContacts->GetRelationship(msg._PeerMain);

		if(!msg.IsGroupMessage())
		{
			if(	(r&MCR_FOLLOWED) && !(r&MCR_FRIENDED) )
				_pContacts->SetRelationship(msg._PeerMain, (MrcContactRelationship)(r|MCR_FRIENDED));
		}

		if(	msg._pGreeting && 
			(msg.GetEnvelope().GetType() != MrcEnvelope::EVLP_BROADCAST || (r&MCR_FRIENDED)) &&
			(r&MCR_KNOWN) &&
			_pContacts->GetType(msg._PeerMain) == MCT_USER
		)
		{	MrcContactProfile profile;
			if(	_pContacts->GetProfile(msg._PeerMain, &profile) && 
				*profile.Address == msg._pGreeting->Sender && 
				env.Time > _pContacts->GetLastModified(msg._PeerMain)
			)
			{
				auto& gr = *msg._pGreeting;
				if(gr.PublicData.IsValid())
				{
					bool modified = false;
					if(profile.Name != gr.GetName()){ profile.Name == gr.GetName();	modified = true; }					
					if(profile.SocialPreference == gr.SocialPreference){ profile.SocialPreference = gr.SocialPreference; modified = true; }
					if(profile.Gender != gr.Gender){ profile.Gender = gr.Gender; modified = true; }
					if(profile.Location != gr.Location){ profile.Location = gr.Location; modified = true; }

					if(	(gr.PublicData.IsZero() && profile.PublicData == nullptr) ||
						gr.PublicData == *profile.PublicData
					)	profile.PublicData = nullptr;
					else
					{	profile.PublicData = &gr.PublicData; modified = true; }

					if(modified)
						_pContacts->SetProfile(msg._PeerMain, &profile, env.Time);
				}
			}
		}
	}

	// TBD: collect node access points from my messages
	// TBD: collect node access points from other's messages

	// media offloads
	if(msg.HasPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS) && _pMediaRelay)
	{
		auto& pld = msg.GetPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS);
		int co = pld.Data[0];
		if(pld.GetOriginalDataSize() == 1 + co*sizeof(MrcMediaOffload))
		{
			auto* offloads = (MrcMediaOffload*)(pld.Data + 1);
			if(msg._pMediaOffloadSecrets && co == msg._pMediaOffloadSecrets->Count)
			{
				for(int i=0; i<co; i++)
					_pMediaRelay->MediaOffloadDiscovered(offloads[i], &msg._pMediaOffloadSecrets->Secrets[i], ctx.SwarmAddr);
			}
			else
			{
				for(int i=0; i<co; i++)
					_pMediaRelay->MediaOffloadDiscovered(offloads[i], nullptr, ctx.SwarmAddr);
			}
		}
	}

	return true;
}

bool MrcContactsControl::_CreateTinyGroupInfoFromAdminMessage(MrcMessageDisassembler& msg_dis, const MrcRecvContext& ctx)
{
	auto& env = msg_dis.GetEnvelope();
	auto& pld = msg_dis.GetPayload(MrcCipherPayload::CPLD_CONTENT);
	auto& msg = pld.Get<MrcCipherPayload::Content>();
	ASSERT(env.App == MrcAppChats);
	ASSERT(env.Action == ACT_TINYGROUP_CREATE);

	auto& gi = *(MrcTinyGroupActionCreate*)msg.Data;
	auto g = _pContacts->GetGroup(&gi.GroupId);
	if(g && _pContacts->GetRelationship(g) == MCR_GROUP_OWNER)
	{
		msg_dis._GroupContact = g;
		msg_dis.ReplaceContentPayload(*_pContacts->GetPublicKey(g), sizeof(PublicKey));
		return true;
	}

	if(gi.GetSize() == pld.GetOriginalDataSize() - offsetof(MrcCipherPayload::Content, Data))
	{
		if(gi.List.MemberCount > MRC_MESSAGE_RECIPENTS_MAX - 1)return false; // admin is not included

		struct g_mem
		{
			const PublicKey*	Member;
			const MrcDataKey*	PublicData;
			bool operator < (const g_mem& x) const { return *Member < *x.Member; }
		};

		MrcContactProfile my_profile;
		_pContacts->GetProfile(_pContacts->GetMyself(), &my_profile);
		auto& my_pk = *my_profile.Address;

		g_mem members[MRC_MESSAGE_RECIPENTS_MAX] = {{ &my_pk, my_profile.PublicData }};
		uint32_t member_count = 1;

		rt::String name = my_profile.Name + ',';

		for(uint32_t i=0; i<gi.List.MemberCount; i++)
		{
			MrcContactProfile profile;
			MrcContact c;

			auto& u = gi.List.Members[i];
			for(uint32_t j=0; j<member_count; j++)
			{
				if(u.Member == *members[j].Member)
					goto DUPLICATED;
			}

			members[member_count++] = { &u.Member, &u.PublicData };
			
			c = _pContacts->GetContact(&u.Member);
			if(c && _pContacts->GetProfile(c, &profile))
				name += profile.Name + ',';

		DUPLICATED:
			continue;
		}

		std::sort(members, members + member_count);

		name = name.TrimRight(1);
		if(name.GetLength() > MRC_PROFILE_NAME_SIZEMAX)
		{
			size_t len = (MRC_PROFILE_NAME_SIZEMAX - 6) / 2;
			rt::String_Ref head(name.Begin(), len);
			rt::String_Ref tail(name.End() - len, len);
			name = head.TrimTrailingIncompleteUTF8Character() + rt::SS(" ... ") + tail.TrimLeadingIncompleteUTF8Character();
		}

		int admin_index = -1;
		for(UINT i=0; i<member_count; i++)
			if(*members[i].Member == my_pk)
			{
				admin_index = i;
				break;
			}

		ASSERT(admin_index >= 0);

		MrcGroupInfo info;
		info.AdminIndex = admin_index;
		info.MemberCount = member_count;
		info.MembershipVersion = 0;
		info.GroupId = &gi.GroupId;

		MrcContactProfile profile;
		profile.Gender = GENDER_TINYGROUP;
		profile.Location = LOCATION_TINYGROUP;
		profile.Name = name;
		profile.Address = &gi.Address;
		profile.PublicData = nullptr;
		profile.SocialPreference = SOCIAL_PREFERENCE_TINYGROUP;

		const PublicKey*	mems[MRC_MESSAGE_RECIPENTS_MAX];
		const MrcDataKey*	pub_data[MRC_MESSAGE_RECIPENTS_MAX];
		for(UINT i=0; i<member_count; i++)
		{
			mems[i] = members[i].Member;
			pub_data[i] = members[i].PublicData;
		}

		auto g = _pContacts->CreateGroup(&profile, &info, mems, pub_data, env.Time, &gi.SecretSeed);
		msg_dis.ReplaceContentPayload(&gi.Address, sizeof(PublicKey));

		return true;
	}

	return false;
}

bool MrcContactsControl::_UpdateTinyGroupInfoFromMessage(MrcMessageDisassembler& msg_dis, MrcRecvContext& ctx)
{
	auto& env = msg_dis.GetEnvelope();
	auto& pld = msg_dis.GetPayload(MrcCipherPayload::CPLD_CONTENT);
	auto& content = pld.Get<MrcCipherPayload::Content>().Data;
	auto  content_size = pld.GetOriginalDataSize() - offsetof(MrcCipherPayload::Content, Data);
	ASSERT(env.App == MrcAppChats);

	auto sender = msg_dis._PeerMain;
	ASSERT(sender);
	ASSERT(msg_dis._pTinyGroupInfo);

	auto& my_pk = *_pContacts->GetPublicKey(_pContacts->GetMyself());
	auto& ginfo = *msg_dis._pTinyGroupInfo;
	auto g = _pContacts->GetGroup(&msg_dis._pTinyGroupInfo->GroupId);
		
	bool IamAddedBySomeone = false;
	if(env.Action == ACT_TINYGROUP_ADD && content_size)
	{
		auto& pld = *(MrcTinyGroupActionMemberAdd*)content;
		if(pld.GetSize() != content_size)return false;

		IamAddedBySomeone = pld.List.Has(my_pk);
	}

	bool group_newly_created = false;
	rt::String_Ref names[MRC_MESSAGE_RECIPENTS_MAX];

	if(g)
	{
		auto relationship = _pContacts->GetRelationship(g);
		if(relationship == MCR_GROUP_MEMBER || relationship == MCR_GROUP_OWNER)
		{
			// only member can send message
			if(_pContacts->GetGroupMemberIndex(g, _pContacts->GetPublicKey(sender)) < 0)return false;
		}
		else
		{
			if(	(relationship == MCR_GROUP_LEFT || relationship == MCR_GROUP_EXPELLED || relationship == MCR_GROUP_DELETED) &&
				env.Action == ACT_TINYGROUP_ADD && content_size
			)	// may someone add me back
			{
				auto& pld = *(MrcTinyGroupActionMemberAdd*)content;
				if(pld.GetSize() != content_size)return false;
				if(!pld.List.Has(my_pk))return false;

				_pContacts->SetRelationship(g, MCR_GROUP_MEMBER); // added me back
			}
			else
				return false; // the group cannot be revive
		}

		// merge group info
		if(_pContacts->GetLastModified(g) < ginfo.LastModified)
		{
			MrcContactProfile profile;
			_pContacts->GetProfile(g, &profile);

			profile.Address = nullptr;
			profile.PublicData = nullptr; // no change
			profile.Location = ginfo.Location;
			profile.SocialPreference = ginfo.SocialPreference;
			if(ginfo.HasAllNames())
				profile.Name = ginfo.GetAllNames().GetGroupName();
			else
				profile.Name.Empty();

			g = _pContacts->SetProfile(g, &profile, env.Time);
			ASSERT(g);
		}

		// skip non-control messages if membership matches
		if (env.Action < ACT_TINYGROUP_MIN || env.Action > ACT_TINYGROUP_MAX)
		{	
			msg_dis._GroupContact = g;
			if(!ginfo.HasMembership())return true;

			auto& mems = ginfo.GetMembership();
			MrcGroupInfo info;
			VERIFY(_pContacts->GetGroupInfo(g, &info));
			if(mems.MembershipVersion == info.MembershipVersion)
				return true;
		}
	}
	else
	{
		if(!ginfo.HasMembership()) return false;		
		auto& m = ginfo.GetMembership();
		if(!m.IsValid())return false;
		// create the tiny group as non-admin

		MrcContactProfile profile;
		rt::String temp;

		if(ginfo.HasAllNames())
		{
			ginfo.GetAllNames().Disassemble(&profile.Name, names, m.Count);
		}
		else if(ginfo.HasGroupName())
		{
			profile.Name = ginfo.GetGroupName();
		}

		profile.Gender = GENDER_TINYGROUP;
		profile.Location = ginfo.Location;
		profile.Address = &m.Address;
		profile.PublicData = nullptr;
		profile.SocialPreference = ginfo.SocialPreference;

		MrcGroupInfo info;
		info.GroupId = &ginfo.GroupId;
		info.MemberCount = m.Count;
		info.AdminIndex = m.AdminIndex;
		info.MembershipVersion = m.MembershipVersion;

		const PublicKey* users[MRC_MESSAGE_RECIPENTS_MAX];
		const MrcDataKey* pub_data[MRC_MESSAGE_RECIPENTS_MAX];

		for(uint32_t i=0; i<m.Count; i++)
		{
			users[i] = &m.Members[i].Member;
			pub_data[i] = &m.Members[i].PublicData;
		}

		g = _pContacts->CreateGroup(&profile, &info, users, pub_data, env.Time, nullptr);

		group_newly_created = true;
	}

	ASSERT(g);
	ctx.Conversation = g;

	if(!group_newly_created && ginfo.HasMembership())
	{	// Merge membership
		ASSERT(g);

		MrcGroupInfo old_info;
		_pContacts->GetGroupInfo(g, &old_info);

		MrcGroupMember old_members[MRC_MESSAGE_RECIPENTS_MAX];
		_pContacts->GetGroupMembers(g, old_members, MRC_MESSAGE_RECIPENTS_MAX);

		auto& mems = ginfo.GetMembership();
		if(mems.MembershipVersion > old_info.MembershipVersion && mems.AdminIndex < mems.Count)
		{
			MrcGroupInfo new_info;
			MrcContact removed[MRC_MESSAGE_RECIPENTS_MAX];
			int removed_count = 0;

			new_info.MembershipVersion = mems.MembershipVersion;
			new_info.AdminIndex = mems.AdminIndex;
			new_info.MemberCount = mems.Count;
			new_info.GroupId = nullptr;
			//for(UINT i=0; i<mems.Count; i++)
			//{
			//	g->Members[i].Address = mems.Members[i].Address;
			//	g->Members[i].JoinTime = mems.Members[i].JoinTime;
			//}

			auto* newm = mems.Members;

			{	// detect members that removed
				UINT old_i = 0, new_i = 0;
				while(old_i < old_info.MemberCount && new_i < mems.Count)
				{
					auto& old_pk = *old_members[old_i].Member;

					if(old_pk == newm[new_i].Member)
					{	old_i++;
						new_i++;
					}
					else if(old_pk < newm[new_i].Member)
					{	// oldm[old_i].Address is removed
						removed[removed_count++] = _pContacts->GetContact(old_members[old_i++].Member);
					}
					else // newm[new_i].Address is added
						new_i++;
				}
				while(old_i < old_info.MemberCount)
					removed[removed_count++] = _pContacts->GetContact(old_members[old_i++].Member);
			}

			const MrcDataKey* pub_data[MRC_MESSAGE_RECIPENTS_MAX];
			MrcGroupMember gmem[MRC_MESSAGE_RECIPENTS_MAX];
			for(uint32_t i=0; i<new_info.MemberCount; i++)
			{
				gmem[i] = { &newm[i].Member, newm[i].JoinTime };
				pub_data[i] = &newm[i].PublicData;
			}

			g = _pContacts->SetGroupMembership(g, &new_info, gmem, env.Time);

			// setup cojoin
			rt::String_Ref names[MRC_MESSAGE_RECIPENTS_MAX];
			if(ginfo.HasAllNames())
				ginfo.GetAllNames().Disassemble(nullptr, names, mems.Count);

			if(_pContacts->SetGroupCoJoinContacts(g, gmem, pub_data, names, new_info.MemberCount))
				_pContacts->UnsetGroupCoJoinContacts(g, removed, removed_count);
			else
				return false;
		}
	}

	msg_dis._GroupContact = g;
	auto& g_pk = *_pContacts->GetPublicKey(g);
	auto& sender_pk = *_pContacts->GetPublicKey(sender);

	auto unset_all_cojoin_members = [this](MrcContact g){
		MrcContact removed[MRC_MESSAGE_RECIPENTS_MAX];
		uint32_t removed_count;

		MrcGroupMember mems[MRC_MESSAGE_RECIPENTS_MAX];
		removed_count = _pContacts->GetGroupMembers(g, mems, MRC_MESSAGE_RECIPENTS_MAX);		
		uint32_t removed_found = 0;
		for (uint32_t i = 0; i < removed_count; i++)
		{
			if (auto c = _pContacts->GetContact(mems[i].Member))
				removed[removed_found++] = c;
		}

		_pContacts->UnsetGroupCoJoinContacts(g, removed, removed_found);
	};

	// handle control messages
	switch (env.Action)
	{
	case ACT_TINYGROUP_CREATE:
	case ACT_TINYGROUP_PROFILE_CHANGE:
		break;
	case ACT_TINYGROUP_DISMISS:
		{
			if(content_size != sizeof(MrcTinyGroupActionDismiss))return false;

			MrcGroupControlSigning sign(g_pk, ginfo.GroupId, env.Time, "dismiss");
			if(sign.Verifiy(g_pk, ((MrcTinyGroupActionDismiss*)content)->GroupIdSigned))
			{
				unset_all_cojoin_members(g);
				_pContacts->SetRelationship(g, MCR_GROUP_DISMISSED);
				msg_dis.ReplaceContentPayload(nullptr, 0, 0);
			}
			else
				return false;
		}
		break;
	case ACT_TINYGROUP_LEAVE:
		{
			if(content_size != sizeof(MrcTinyGroupActionMemberLeave))return false;

			MrcGroupControlSigning sign(g_pk, ginfo.GroupId, env.Time, "leave");
			if(!sign.Verifiy(sender_pk, ((MrcTinyGroupActionMemberLeave*)content)->LeaveSigned))
				return false;

			if(sender_pk == my_pk)
			{
				unset_all_cojoin_members(g);
				_pContacts->SetRelationship(g, MCR_GROUP_LEFT);
			}
			else
			{
				int r = _pContacts->GetGroupMemberIndex(g, &sender_pk);
				if(r>=0)
				{
					MrcGroupInfo info;
					_pContacts->GetGroupInfo(g, &info);

					if(r == info.AdminIndex)return false; // admin leave, should use dismiss op

					MrcGroupMember mems[MRC_MESSAGE_RECIPENTS_MAX];
					auto mem_co = _pContacts->GetGroupMembers(g, mems, MRC_MESSAGE_RECIPENTS_MAX);

					info.GroupId = nullptr;
					info.MembershipVersion++;
					info.MemberCount--;
					memmove(&mems[r], &mems[r+1], sizeof(MrcGroupMember)*((int)info.MemberCount - r));
					if(r < info.AdminIndex)info.AdminIndex--;
					g = _pContacts->SetGroupMembership(g, &info, mems, env.Time);

					_pContacts->UnsetGroupCoJoinContacts(g, &sender, 1);
				}
			}

			msg_dis.ReplaceContentPayload(nullptr, 0, 0);
		}
		break;
	case ACT_TINYGROUP_EXPEL:
		{
			if(content_size == 0 || !ginfo.HasMembership())return false;

			auto& pld = *(MrcTinyGroupActionMemberRemove*)content;
			if(pld.GetSize() != content_size)return false;

			MrcGroupInfo info;
			_pContacts->GetGroupInfo(g, &info);

			MrcGroupMember mems[MRC_MESSAGE_RECIPENTS_MAX];
			_pContacts->GetGroupMembers(g, mems, MRC_MESSAGE_RECIPENTS_MAX);

			auto& msg_mems = ginfo.GetMembership();
			for(UINT i=0; i<pld.Count; i++)
			{
				if(pld.RemovalIndex[i] < info.MemberCount)
				{
					auto& removed_addr = msg_mems.Members[pld.RemovalIndex[i]].Member;
					int idx = _pContacts->GetGroupMemberIndex(g, &removed_addr);
					if(idx == info.AdminIndex)return false; // admin is removed
					if(idx>=0)
					{
						if(removed_addr == my_pk)
							_pContacts->SetRelationship(g, MCR_GROUP_EXPELLED);

						mems[idx].JoinTime = 0;
					}
				}
			}

			MrcContact		remove[MRC_MESSAGE_RECIPENTS_MAX];
			MrcGroupMemberList	remove_list;
			uint32_t		remove_count = 0;

			uint32_t remain = 0;
			uint32_t admin_index_moved = 0;
			for(uint32_t i=0; i<info.MemberCount; i++)
			{
				if(mems[i].JoinTime)
					mems[remain++] = mems[i];
				else
				{
					if (i < info.AdminIndex)
						admin_index_moved++;

					remove_list.Members[remove_count] = *mems[i].Member;
					remove[remove_count] = _pContacts->GetContact(mems[i].Member);
					remove_count++;
				}
			}

			info.AdminIndex -= admin_index_moved;
			info.GroupId = nullptr;
			info.MemberCount = remain;
			info.MembershipVersion++;

			remove_list.Count = remove_count;

			g = _pContacts->SetGroupMembership(g, &info, mems, env.Time);
			_pContacts->UnsetGroupCoJoinContacts(g, remove, remove_count);

			msg_dis.ReplaceContentPayload(&remove_list, remove_list.GetSize());
		}
		break;
	case ACT_TINYGROUP_ADD:
		{
			if(content_size == 0)return false;
			auto& pld = *(MrcTinyGroupActionMemberAdd*)content;
			if(pld.GetSize() != content_size)return false;

			MrcGroupInfo info;
			_pContacts->GetGroupInfo(g, &info);

			if(pld.List.MemberCount + info.MemberCount > MRC_MESSAGE_RECIPENTS_MAX)
				return false;

			MrcGroupMember mems[MRC_MESSAGE_RECIPENTS_MAX];
			_pContacts->GetGroupMembers(g, mems, MRC_MESSAGE_RECIPENTS_MAX);

			MrcGroupMemberList	new_list;
			MrcGroupMember	new_member[MRC_MESSAGE_RECIPENTS_MAX];
			MrcDataKey*		new_pub_data[MRC_MESSAGE_RECIPENTS_MAX];
			uint32_t		new_co = 0;
			
			for(uint32_t i=0; i<pld.List.MemberCount; i++)
			{
				auto& new_pk = pld.List.Members[i].Member;
				uint32_t n=0;
				for(; n<info.MemberCount; n++)
				{
					int c = new_pk.Compare(*(mems[n].Member));
					if(c < 0)break;
					if(c == 0)goto DUPLICATED;
				}

				// insert at n
				memmove(&mems[n+1], &mems[n], (info.MemberCount - n)*sizeof(MrcGroupMember));
				info.MemberCount++;

				if(n <= info.AdminIndex)info.AdminIndex++;

				mems[n] = { &new_pk, env.Time };
				new_member[new_co] = mems[n];
				new_pub_data[new_co] = &pld.List.Members[i].PublicData;
				new_list.Members[new_co] = pld.List.Members[i].Member;

				new_co++;

			DUPLICATED:
				continue;
			}

			if(new_co)
			{
				new_list.Count = new_co;
				
				info.GroupId = nullptr;
				info.MembershipVersion++;

				if (_pContacts->SetGroupCoJoinContacts(g, new_member, new_pub_data, nullptr, new_co))
				{
					g = _pContacts->SetGroupMembership(g, &info, mems, env.Time);
					msg_dis.ReplaceContentPayload(&new_list, new_list.GetSize());
				}
				else
					return false;
			}
			else
			{
				new_list.Count = pld.List.MemberCount;

				for (uint32_t i=0; i < pld.List.MemberCount; i++)
					new_list.Members[i] = pld.List.Members[i].Member;

				msg_dis.ReplaceContentPayload(&new_list, new_list.GetSize());
			}
		}
		break;
	}

	msg_dis._GroupContact = g;
	return true;
}

namespace control_msgs
{

MrcGroupControlSigning::MrcGroupControlSigning(const PublicKey& g, const MrcContactGroupId& gid, NetTimestamp time, const rt::String_Ref& addition)
{
	ASSERT(addition.GetLength() < sizeof(AdditionData));

	Address = g;
	GroupId = gid;
	Timestamp = time;
	addition.CopyTo((LPSTR)AdditionData);
	TotalSize = offsetof(MrcGroupControlSigning, AdditionData) + (UINT)addition.GetLength();
}

bool MrcTinyGroupMemberList::Has(const PublicKey& pk) const
{
	for(UINT i=0; i<MemberCount; i++)
		if(Members[i].Member == pk)
			return true;

	return false;
}

bool MrcTinyGroupMemberList::Compose(MrcContactsRepository* contacts, UINT size_limit, const MrcContact* members, UINT member_count)
{
	if(member_count > MRC_MESSAGE_RECIPENTS_MAX)return false;

	MemberCount = member_count;
	if(GetSize() <= size_limit)
	{
		for(UINT i=0; i<member_count; i++)
		{
			MrcContactProfile profile;
			if(!contacts->GetProfile(members[i], &profile))return false;

			Members[i] = { *profile.Address, *profile.PublicData };
		}

		return true;
	}

	return false;
}

} // namespace group_msgs
} // namespace upw
