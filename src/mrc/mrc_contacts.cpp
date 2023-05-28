#include "mrc.h"
#include "mrc_contacts.h"


namespace upw
{

MrcContacts::MrcContacts(MessageRelayCore& c)
	:_Core(c)
{
	rt::Zero(_Myself);
	_Revision = 0;
}

void MrcContacts::_UpdateContactPoints()
{
	os::AtomicIncrement(&_Revision);
	_Core.UpdateContactPoints(true);
}

void MrcContacts::GetNonce(NonceData* nonce_out)
{
	sec::Randomize(*nonce_out);
	(*nonce_out) ^= (NonceData&)_Myself.Address;
}

void MrcContacts::SignOnBehalfOfMe(SignatureData* sig_out, const void* data, uint32_t data_size)
{
	EnterCSBlock(_MyCS);
	ASSERT(_Myself.Relationship);
	_MySocialIdSK.Reveal().Sign(*sig_out, data, data_size);
}

bool MrcContacts::MrcContacts::DecryptAnonymousDataToMe(const void* data, uint32_t data_size, void* plain_out)
{
	EnterCSBlock(_MyCS);
	if(_Myself.Relationship)return false;
	return _MySocialIdDecrypt.Decrypt(data, data_size, plain_out, _MySocialIdEncrypt);
}

bool MrcContacts::IsMyself(MrcContact contact)
{
	auto* u = (User*)contact;
	if(_Myself.Relationship)return false;
	return u == &_Myself || (u &&  u->Type == MCT_USER && u->Address == _Myself.Address);
}

MrcContact MrcContacts::MrcContacts::GetMyself()
{
	if(_Myself.Relationship)
		return (MrcContact)&_Myself;
	else
		return 0;
}

void MrcContacts::_RemoveAllContacts()
{
	EnterCSBlock(_CS);
	for(auto& it : _Contacts)
		_SafeFree8AL_ConstPtr(it.second);

	_Contacts.clear();
}

bool MrcContacts::SetMyself(const MrcRootSecretSeed* seed, const MrcContactProfile* my)
{
	_Myself.Relationship = MCR_NONE;

	MrcKeyPair sid, pubdata;
	seed->DeriveSocialIdKeypair(sid);
	seed->DerivePublicDataKeyPair(pubdata);

	_RemoveAllContacts();

	EnterCSBlock(_MyCS);
	_MyRootSeed.Hide(*seed);
	_MySocialIdSK.Hide(sid.Private());
	_MySocialIdEncrypt = sid.Public();
	_MySocialIdDecrypt = sid.Private();

	_Myself.Address = sid.Public();
	_Myself.PublicData = pubdata.DataKey();
	rt::Zero(_Myself.Secret);
	_Myself.SocialPreference = 0;
	_Myself.Type = MCT_USER;
	_Myself.LastModified = 0;

	if(my)
	{
		_Myself.Gender = my->Gender;
		_Myself.Location = my->Location;

		rt::String_Ref n = my->Name.SubStrHead(MRC_PROFILE_NAME_SIZEMAX);
		_Myself.Name.SetSize(n.GetLength());
		_Myself.Name.CopyFrom(n.Begin());
	}
	else
	{
		_Myself.Gender = 0;
		_Myself.Location = 0;

		rt::String n;
		_Myself.Address.GetDefaultName(n);
		_Myself.Name.SetSize(n.GetLength());
		_Myself.Name.CopyFrom(n.Begin());
	}

	_Myself.Relationship = (MrcContactRelationship)(MCR_FRIENDED | MCR_FOLLOWED);
	_UpdateContactPoints();
	return true;
}

MrcContactType MrcContacts::GetType(MrcContact contact)
{
	if(contact)return ((Contact*)contact)->Type;
	return MCT_INVALID;
}

MrcContactRelationship MrcContacts::GetRelationship(MrcContact contact)
{
	if(contact)
	{
		auto* c = (ContactConversion*)contact;
		if(c->Type >= MCT_CONVERSATION)
			return c->Relationship;
	}
	return MCR_NONE;
}

MrcContactPreference MrcContacts::GetSocialPreference(MrcContact contact)
{
	auto* u = (User*)contact;
	if(u && u->Type >= MCT_CONVERSATION)
		return (MrcContactPreference)u->SocialPreference;

	return MSP_NONE;
}

MrcContact MrcContacts::GetContact(const PublicKey* pk)
{
	EnterCSBlock(_CS);
	auto* c = _Contacts.get(*pk);
	if(c)return (MrcContact)c;
	return 0;
}

const PublicKey* MrcContacts::GetPublicKey(MrcContact contact)
{
	auto* c = (ContactConversion*)contact;
	if(c && c->Type >= MCT_CONVERSATION)
		return &c->Address;

	return nullptr;
}

int64_t	MrcContacts::GetLastModified(MrcContact contact)
{
	if(contact)return ((Contact*)contact)->LastModified;
	return 0;
}

bool MrcContacts::GetProfile(MrcContact contact, MrcContactProfile* out)
{
	if(contact)
	{
		auto* c = (ContactConversion*)contact;
		switch (c->Type)
		{
		case MCT_USER:
			{	auto* u = (User*)c;
				out->PublicData = &u->PublicData;
			}	break;
		case MCT_GROUP:
			{	auto* g = (Group*)c;
				out->PublicData = nullptr;
			}	break;
		default: return false;
		}

		out->Gender = c->Gender;
		out->SocialPreference = c->SocialPreference;
		out->Address = &c->Address;
		out->Name = rt::String_Ref(c->Name.begin(), c->Name.GetSize());
		out->Location = c->Location;

		return true;
	}
	return false;
}

uint32_t MrcContacts::ScanContacts(MrcContactIterator * iter, int64_t time)
{
	uint32_t i=0;
	EnterCSBlock(_CS);
	for(auto& it : _Contacts)
	{
		if(it.second->Type >= MCT_CONVERSATION)
			if(!iter->OnContact((MrcContact)it.second))
				break;
		i++;
	}

	return i;
}

const CipherSecret*	MrcContacts::GetSecret(MrcContact contact)
{
	if(contact)
	{
		auto* c = (ContactConversion*)contact;
		return (CipherSecret*)&c->Secret;
	}
	return nullptr;
}

const CipherSecret*	MrcContacts::GetUserGreetingSecret(MrcContact contact)
{
	auto* u = (User*)contact;
	if(u && u->Type == MCT_USER && (u->Relationship&~MCR_COJOIN))return &u->GreetingSecret;
	return nullptr;
}

bool MrcContacts::EncryptKeyToUser(MrcContact recipent, const NonceData* nonce, const CipherSecret* plain_key, SealedCipherSecret* encrypted_key_out)
{
	auto* u = (User*)recipent;
	if(u && u->Type == MCT_USER)
	{
		u->SealBox.Encrypt(*nonce, rt::DS(plain_key, sizeof(CipherSecret)), encrypted_key_out);
		return true;
	}

	return false;
}

bool MrcContacts::DecryptKeyFromUser(MrcContact sender, const NonceData* nonce, const SealedCipherSecret* encrypted_key, CipherSecret* plain_key_out)
{
	auto* u = (User*)sender;
	if(u && u->Type == MCT_USER)
	{
		u->SealBox.Decrypt(*nonce, rt::DS(encrypted_key, sizeof(SealedCipherSecret)), plain_key_out);
		return true;
	}

	return false;
}

bool MrcContacts::VerifySignature(MrcContact contact, const void* data, uint32_t data_size, const SignatureData* sig)
{
	auto* c = (ContactConversion*)contact;
	if(c && c->Type >= MCT_CONVERSATION)
	{
		return c->Address.Verify(*sig, rt::DS(data, data_size));
	}

	return false;
}

void MrcContacts::_CopyProfileName(const rt::String_Ref& name, ContactConversion* c) const
{
	if(!name.IsEmpty())
	{
		rt::String_Ref n = name.SubStrHead(MRC_PROFILE_NAME_SIZEMAX);
		c->Name.SetSize(n.GetLength());
		c->Name.CopyFrom(n.Begin());
	}
}

void MrcContacts::_CopyProfile(const MrcContactProfile* profile, ContactConversion* c) const
{
	c->Gender = profile->Gender;
	c->Location = profile->Location;
	c->SocialPreference = profile->SocialPreference;

	_CopyProfileName(profile->Name, c);
}

void MrcContacts::_SetupUserSecurity(User* p) const
{
	auto sk = _MySocialIdSK.Reveal();
	p->Secret.Compute(p->Address, sk);
	sec::Hash<sec::HASH_SHA256>().Calculate(p->Secret, p->Secret.LEN, &p->Secret);
	p->SealBox.SetKeys(p->Address, sk);
}

MrcContact MrcContacts::CreateUser(const MrcContactProfile* profile, bool by_greeting, const upw::CipherSecret* greeting_secret)
{
	if(*profile->Address == _Myself.Address)return (MrcContact)&_Myself;
	
	User* p = nullptr;
	{	EnterCSBlock(_MyCS);
		p = (User*)_Contacts.get(*profile->Address);
		if(!p)
		{
			p = _Create<User>();
			p->Type = MCT_USER;
			p->Address = *profile->Address;
			rt::Zero(p->GreetingSecret);
			p->LastModified = 0;
			p->Relationship = MCR_FOLLOWED;

			_SetupUserSecurity(p);
		}
		else
		{
			if(p->Type != MCT_USER || p->Address != *profile->Address)
				return (MrcContact)0;

			if(!by_greeting)p->Relationship = (MrcContactRelationship)(MCR_FRIENDED|p->Relationship);
		}

		if(p->LastModified == 0)
		{
			_CopyProfile(profile, p);
			if(profile->PublicData)
				p->PublicData = *profile->PublicData;
			else
				rt::Zero(p->PublicData);
		}

		if(by_greeting)
		{
			ASSERT(greeting_secret);
			p->GreetingSecret = *greeting_secret;
		}
	}

	{	EnterCSBlock(_CS);
		_Contacts[p->Address] = p;
	}

	_UpdateContactPoints();
	return (MrcContact)p;
}

void MrcContacts::RemoveContact(MrcContact contact)
{
	auto* u = (ContactConversion*)contact;
	if(u && u->Type >= MCT_CONVERSATION)
	{
		EnterCSBlock(_CS);
		auto it = _Contacts.find(u->Address);
		ASSERT(it != _Contacts.end());
		_Contacts.erase(it);
		_SafeDel_Delayed(u, 2000);
	}

	_UpdateContactPoints();
}

MrcContact MrcContacts::SetProfile(MrcContact contact, const MrcContactProfile* in, NetTimestamp modified_time)
{
	if(contact)
	{
		auto* c = (ContactConversion*)contact;
		if(c->Type < MCT_CONVERSATION)return (MrcContact)0;

		_CopyProfile(in, c);

		if(c->Type == MCT_USER)
		{
			auto* u = (User*)c;
			if(in->PublicData)u->PublicData = *in->PublicData;
		}

		return contact;
	}

	return 0;
}

MrcContactRelationship	MrcContacts::SetRelationship(MrcContact contact, MrcContactRelationship new_relation)
{
	auto* u = (User*)contact;
	if(u && u->Type == MCT_USER)
	{
		auto ret = u->Relationship;
		u->Relationship = new_relation;

		_UpdateContactPoints();
		return ret;
	}

	return MCR_NONE;
}

MrcContact MrcContacts::GetGroup(const MrcContactGroupId* id)
{
	EnterCSBlock(_CS);
	return (MrcContact)_Groups.get(*id);
}

bool MrcContacts::GetGroupInfo(MrcContact group, MrcGroupInfo* out)
{
	auto* g = (Group*)group;
	if(g && g->Type == MCT_GROUP)
	{
		out->MemberCount = g->MemberCount;
		out->AdminIndex = g->AdminIndex;
		out->MembershipVersion = g->MembershipVersion;
		out->GroupId = &g->GroupId;

		return true;
	}

	return false;
}

uint32_t MrcContacts::GetGroupMembers(MrcContact group, MrcGroupMember* members, uint32_t member_count)
{
	auto* g = (Group*)group;
	if(g && g->Type == MCT_GROUP)
	{
		member_count = rt::min(member_count, (uint32_t)g->MemberCount);
		for(uint32_t i=0; i<member_count; i++)
		{
			members[i] = { &g->Members[i].Address, g->Members[i].JoinTime };
		}

		return member_count;
	}

	return 0;
}

int	MrcContacts::GetGroupMemberIndex(MrcContact group, const PublicKey* user)
{
	auto* g = (Group*)group;
	if(g && g->Type == MCT_GROUP)
	{
		for(int i=0; i<g->MemberCount; i++)
			if(user == &g->Members[i].Address || *user == g->Members[i].Address)
				return i;
	}

	return -1;
}

MrcContact MrcContacts::CreateGroup(const MrcContactProfile* group, const MrcGroupInfo* info, const PublicKey*const* members, const MrcDataKey*const* public_data, NetTimestamp modified_time, const MrcRootSecretSeed* pAdminSecret)
{
	{	EnterCSBlock(_CS);
		Group* g = _Groups.get(*info->GroupId);
		if(!g)
		{
			g = _Create<Group>();
			g->Type = MCT_GROUP;
			g->Address = *group->Address;
			_CopyProfile(group, g);

			g->AdminIndex = info->AdminIndex;
			g->GroupId = *info->GroupId;
			g->LastModified = modified_time;
			g->MemberCount = info->MemberCount;

			for(uint32_t i=0; i<info->MemberCount; i++)
				g->Members[i] = { *members[i], modified_time };

			g->MembershipVersion = info->MembershipVersion;
			g->Relationship = MCR_GROUP_MEMBER;

			_Contacts[g->Address] = g;
			_Groups[g->GroupId] = g;
		}
		else
		{
			if(g->Type != MCT_GROUP)return (MrcContact)0;

			if(g->LastModified < modified_time)
			{
				_CopyProfile(group, g);
			}
		}

		if(pAdminSecret && g->Relationship != MCR_GROUP_OWNER)
		{
			g->RootSeed.Hide(*pAdminSecret);

			MrcKeyPair kp;
			pAdminSecret->DeriveSocialIdKeypair(kp);
			g->SocialIdSK.Hide(kp.Private());
			g->Relationship = MCR_GROUP_OWNER;
		}
	}

	_UpdateContactPoints();
	return 0;
}

MrcContact MrcContacts::SetGroupMembership(MrcContact group, const MrcGroupInfo* info, const MrcGroupMember* members, NetTimestamp time)
{
	auto* g = (Group*)group;
	if(g && g->Type == MCT_GROUP)
	{
		g->AdminIndex = info->AdminIndex;
		g->MemberCount = info->MemberCount;
		g->MembershipVersion = info->MembershipVersion;

		for(int i=0; i<g->MemberCount; i++)
			g->Members[i] = { *members[i].Member, members[i].JoinTime };

		g->LastModified = time;
		return (MrcContact)g;
	}

	return 0;
}

bool MrcContacts::SetGroupCoJoinContacts(MrcContact group, const MrcGroupMember* users, const MrcDataKey*const* public_data, const rt::String_Ref* names, uint32_t count)
{
	bool cp_modified = false;

	{	EnterCSBlock(_CS);
		for(uint32_t i=0; i<count; i++)
		{
			auto* u = (User*)_Contacts.get(*users[i].Member);
			if(u->Type != MCT_USER)continue;

			if(!u)
			{
				u = _Create<User>();
				u->Type = MCT_USER;
				u->Address = *users[i].Member;
				u->PublicData = *(public_data[i]);
				_CopyProfileName(names[i], u);

				rt::Zero(u->GreetingSecret);
				u->LastModified = 0;
				u->Relationship = MCR_NONE;

				_SetupUserSecurity(u);
				_Contacts[u->Address] = u;
			}

			if(u->Relationship == MCR_NONE)
				cp_modified = true;

			u->Relationship = MCR_COJOIN;
		}
	}

	if(cp_modified)_UpdateContactPoints();
	return true;
}

void MrcContacts::UnsetGroupCoJoinContacts(MrcContact group, const MrcContact* users, uint32_t count)
{
	bool cp_modified = false;

	{	EnterCSBlock(_CS);
		for(uint32_t i=0; i<count; i++)
		{
			auto* u = (User*)users[i];
			if(u && u->Type == MCT_USER && (u->Relationship&MCR_COJOIN))
			{
				auto& pk = u->Address;
				for(auto& it : _Groups)
				{
					auto& g = *it.second;
					for(uint32_t m=0; m<g.MemberCount; m++)
						if(g.Members[m].Address == pk)
							goto STILL_COJOIN;
				}

				u->Relationship = (MrcContactRelationship)(u->Relationship^(~MCR_COJOIN));

				if(u->Relationship == 0)
					cp_modified = true;
			}
		STILL_COJOIN:
			continue;
		}
	}

	if(cp_modified)_UpdateContactPoints();
}

} // namespace upw
