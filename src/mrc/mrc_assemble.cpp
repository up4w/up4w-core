#include "mrc.h"
#include "mrc_assemble.h"
#include "mrc_credential.h"
#include "mrc_attachments.h"


namespace upw
{

thread_local rt::BufferEx<BYTE> g_MsgAsmBuf;

MrcMessageAssembler::MrcMessageAssembler(MessageRelayCore& x)
	:_Core(x)
{
}

MrcContactsRepository* MrcMessageAssembler::_Contacts() const
{
	return _Core.GetContacts();
}

bool MrcMessageAssembler::_AllocateSealedBox(UINT count)
{
	_Env()->SetType(MrcEnvelope::EVLP_SEALBOX);
	ASSERT(count + _AdditionalRecipientCount <= MRC_MESSAGE_RECIPENTS_MAX);

	for(UINT i=0; i<count; i++)
	{
		ASSERT(_Recipients[i]);
		if(_Contacts()->GetType(_Recipients[i]) != MCT_USER)
			return false;
	}

	// include additional recipients
	for(UINT i=0; i<_AdditionalRecipientCount; i++)
		_Recipients[count + i] = _AdditionalRecipients[i];

	count += _AdditionalRecipientCount;

	UINT sz = MrcCredential_SealedBox::GetSize(count);
	if(sz > NET_DATAGRAMNETWORK_MTU)return false;

	auto* box = (MrcCredential_SealedBox*)_Envelope.push_back_n(sz);
	if(!box)return false;

	box->RecipientCount = count;
	return true;
}

void MrcMessageAssembler::SetAdditionalRecipients(const MrcContact* reps, uint32_t co)
{
	_AdditionalRecipients = reps;
	_AdditionalRecipientCount = co;
}

void MrcMessageAssembler::_Init(MrcAppId app, WORD action, uint64_t ts, bool recipients_inited)
{
	VERIFY(_Envelope.SetSize(offsetof(MrcEnvelope, CredentialData)));

	auto& env = *_Env();
	env.Time = ts;
	env.App = app;
	env.Action = action;
	env.Reserved = 0;
	env.Type_CPLD = 0;
		
	if(!recipients_inited)
	{
		rt::Zero(_Recipients);
		//_pGroupRecipient = nullptr;
	}
	
	_PayloadOffset = 0;
	_PayloadStartOffset = 0;
	_pContent = nullptr;
	_pObservatoryData = nullptr;
	_bIsCommunityCast = false;
}

bool MrcMessageAssembler::Create(MrcContact recipient, MrcAppId app, WORD action, uint64_t ts)
{
	auto type = _Contacts()->GetType(recipient);

	if(type == MCT_USER || type == MCT_COMMUNITY)
		return Create(&recipient, 1, app, action, ts);

	if(type == MCT_GROUP)
	{
		_Contacts()->GetGroupInfo(recipient, &_GroupInfo);
		_Contacts()->GetGroupMembers(recipient, _GroupMembers, MRC_MESSAGE_RECIPENTS_MAX);
		if(_GroupInfo.MemberCount < 1 || _GroupInfo.MemberCount > MRC_MESSAGE_RECIPENTS_MAX)
			return false;

		UINT recipient_count = 0;

		auto myself = _Contacts()->GetMyself();

		if(_GroupInfo.MemberCount > 1)
		{
			auto& my_pk = *_Contacts()->GetPublicKey(myself);
			bool joined = false;

			for(UINT i=0; i<_GroupInfo.MemberCount; i++)
			{
				if(*_GroupMembers[i].Member == my_pk)
				{
					joined = true;
					continue;
				}

				MrcContact mems = _Contacts()->GetContact(_GroupMembers[i].Member);
				if(!mems)return false;

				if(_Contacts()->GetType(mems) != MCT_USER)return false;
				_Recipients[recipient_count++] = mems;
			}

			if(!joined)return false;
			ASSERT(recipient_count + 1 == _GroupInfo.MemberCount);
		}
		else
		{
			MrcContact mems = _Contacts()->GetContact(_GroupMembers[0].Member);
			if(!mems)return false;

			if(*_Contacts()->GetPublicKey(myself) != *_Contacts()->GetPublicKey(mems))
				return false;

			recipient_count = 1;
			_Recipients[0] = mems;
		}

		_GroupRecipient = recipient;
		return Create(_Recipients, recipient_count, app, action, ts);
	}

	return false;
}

bool MrcMessageAssembler::Create(const MrcContact* recipient, UINT count, MrcAppId app, WORD action, uint64_t ts)
{
	ASSERT(count);
	if(count > MRC_MESSAGE_RECIPENTS_MAX)return false;
	auto type_0 = _Contacts()->GetType(recipient[0]);

	if(count == 1 && type_0 == MCT_COMMUNITY)
	{
		_Init(app, action, ts);
		_Env()->SetType(MrcEnvelope::EVLP_COMMUNITYSEND);
		VERIFY(_Envelope.push_back_n(MrcCredential_CommunitySend::GetSize()));

		_Recipients[0] = recipient[0];
		_PayloadOffset = _Envelope.GetSize();
		return true;
	}

	// for EVLP_SEALBOX, EVLP_SEALGREETING
	if(recipient == _Recipients)
	{
		_Init(app, action, ts, true);
	}
	else
	{
		_Init(app, action, ts);
		memcpy(_Recipients, recipient, count*sizeof(MrcContact));
	}

	if(type_0 == MCT_USER)
	{
		if(count == 1 && (_Contacts()->GetRelationship(recipient[0])&MCR_ENGAGED) == 0)
		{
			_Env()->SetType(MrcEnvelope::EVLP_SEALGREETING);
			VERIFY(_Envelope.push_back_n(MrcCredential_SealedGreeting::GetSize()));
		}
		else
		{
			if(!_AllocateSealedBox(count))return false;
		}

		auto& env = *_Env();
		sec::Randomize(env.GetNonce());

		_PayloadOffset = _Envelope.GetSize();
		return true;
	}

	return false;
}

void MrcMessageAssembler::_InitBroadcast(MrcAppId app, WORD action, uint64_t ts, bool recipients_inited)
{
	_Init(app, action, ts, recipients_inited);
	_Env()->SetType(MrcEnvelope::EVLP_BROADCAST);
	VERIFY(_Envelope.push_back_n(MrcCredential_Broadcast::GetSize()));

	_PayloadOffset = _Envelope.GetSize();
}

bool MrcMessageAssembler::CreateCommunityCast(MrcContact recipient, MrcAppId app, WORD action, uint64_t ts)
{
	ASSERT(_Contacts()->GetType(recipient) == MCT_COMMUNITY);

	_Recipients[0] = recipient;
	_InitBroadcast(app, action, ts, true);

	_bIsCommunityCast = true;
	return true;
}

bool MrcMessageAssembler::CreateFollowerCast(MrcAppId app, WORD action, uint64_t ts)
{
	_InitBroadcast(app, action, ts);
	return true;
}

void MrcMessageAssembler::_BeginPayload(MrcCipherPayload::Type type, bool encrypted)
{
	ASSERT(!_PayloadStartOffset);
	ASSERT(type <= MrcCipherPayload::CPLD_BITMASK);
	ASSERT((_Env()->Type_CPLD&(1<<type)) == 0);

	_Env()->Type_CPLD |= (1<<type);

	_PayloadStartOffset = _Envelope.GetSize();
	auto* p = (MrcCipherPayload*)_Envelope.push_back_n(offsetof(MrcCipherPayload, Data));
	p->EncBit_BlockCount = (BYTE)(encrypted?MrcCipherPayload::ENCRYPTION_BIT:0U);
	p->Payload_Padding = (BYTE)type;
}

LPBYTE MrcMessageAssembler::_AppendPayload(UINT size)
{
	ASSERT(_PayloadStartOffset);
	return _Envelope.push_back_n(size);
}

void MrcMessageAssembler::_TrimAppendedPayload(UINT size)
{
	ASSERT(size <= _Envelope.GetSize());
	_Envelope.ShrinkSize(_Envelope.GetSize() - size);
}

void MrcMessageAssembler::_EndPayload()
{
	ASSERT(_PayloadStartOffset);
	ASSERT(_PayloadStartOffset < _Envelope.GetSize());

	UINT data_size = _Envelope.GetSize() - _PayloadStartOffset - offsetof(MrcCipherPayload, Data);
	if(_Pld()->IsEncrypted())
	{
		UINT align_size = Cipher::AlignSize(data_size);
		UINT padding = align_size - data_size;
		if(padding)
		{
			auto* p = _Envelope.push_back_n(padding);
			memset(p, 0, padding);
			_Pld()->Payload_Padding |= (padding<<4);
		}
		_Pld()->EncBit_BlockCount += align_size/Cipher::DataBlockSize;
	}
	else
	{
		_Pld()->EncBit_BlockCount = data_size/Cipher::DataBlockSize;
		UINT padding = data_size - _Pld()->EncBit_BlockCount*Cipher::DataBlockSize;

		_Pld()->Payload_Padding |= (padding<<4);
	}

	_PayloadStartOffset = 0;
}

MrcContactPointNum MrcMessageAssembler::_GetContactPoint(LPCVOID data, UINT size) const 
{ 
	ASSERT(size >= 16); 
	return GetContactPoint(_Env()->Time, data, size);
}

void MrcMessageAssembler::_SetupRecipient(MrcRecipient& r, const NonceData& nonce, const CipherSecret& key, MrcContact recipent, const PublicKey& my_pk, const NetTimestamp& time)
{
	r.Reserved = 0;
	r.Flag_Direction = 0;
	auto* to_pk = _Contacts()->GetPublicKey(recipent);
	ASSERT(to_pk);

	if(my_pk < *to_pk)
		r.Flag_Direction |= MrcRecipient::SendingUp;

	r.ContactPoint = _GetContactPoint(_Contacts()->GetSecret(recipent), sizeof(MutualSecret));
	VERIFY(_Contacts()->EncryptKeyToUser(recipent, &nonce, &key, &r.SealedSecret));
}

void MrcMessageAssembler::_Seal()
{
	ASSERT(!_PayloadStartOffset);
	ASSERT(_PayloadOffset);

	auto& e = *_Env();
	if(e.Time == 0)
		e.Time = _Core.GetTime();

	rt::PodOnHeap<CipherSecret> master_key;

	if(e.HasNonce())
	{
		auto& h = GetHasher();
		_Core.GetContacts()->GetNonce(&e.GetNonce());
		h.Update(e.GetNonce());

		// master key is before encryption
		uint32_t iter;
		auto* pld = e.GetFirstPayload(iter);
		while(pld)
		{
			h.Update(pld->Data, pld->GetOriginalDataSize());
			pld = e.GetNextPayload(pld, iter);
		}

		h.Update(&e, offsetof(MrcEnvelope, CredentialData));
		h.Finalize(master_key);
		static_assert(sizeof(CipherSecret) == sec::Hash<sec::HASH_SHA256>::HASHSIZE, "CipherSecret should have a size same as hash value");
	}

	auto myself = _Contacts()->GetMyself();

	// encrypt payloads
	{	Cipher enc;
		if(e.HasNonce())
			enc.SetKey(*master_key);
		else
		{	switch(e.GetType())
			{
			case MrcEnvelope::EVLP_BROADCAST:
				if(_Contacts()->GetType(_Recipients[0]) == MCT_COMMUNITY) // community cast
					enc.SetKey(*_Contacts()->GetSecret(_Recipients[0]));
				else
					enc.SetKey(*_Core.GetContacts()->GetPublicKey(myself));
				break;
			case MrcEnvelope::EVLP_COMMUNITYSEND:
				ASSERT(_Contacts()->GetType(_Recipients[0]) == MCT_COMMUNITY);
				enc.SetKey(*_Contacts()->GetSecret(_Recipients[0]));
				break;
			default: ASSERT(0);
			}
		}

		uint32_t iter;
		auto* pld = e.GetFirstPayload(iter);
		while(pld)
		{
			if(pld->IsEncrypted())
			{
				g_MsgAsmBuf.SetSize(pld->GetDataSize());
				g_MsgAsmBuf.CopyFrom(pld->Data);

				enc.Encode(g_MsgAsmBuf, (LPVOID)pld->Data, g_MsgAsmBuf.GetSize(), pld->GetNonce());
			}

			pld = e.GetNextPayload(pld, iter);
		}
	}

	if(IsSignatureRequired())
	{
		// master key is the hash value for signing
		auto& h = GetHasher();
		h.Update(e.Time);

		if(IsCommunitySend())
			h.Update(*_Contacts()->GetPublicKey(_Recipients[0]));

		uint32_t iter;
		auto* pld = e.GetFirstPayload(iter);
		while(pld)
		{
			if(pld->IsEncrypted())
				h.Update(pld->Data, pld->GetDataSize());
			else
				h.Update(pld->Data, pld->GetOriginalDataSize());

			pld = e.GetNextPayload(pld, iter);
		}

		h.Update(&e, offsetof(MrcEnvelope, CredentialData));
		h.Finalize(master_key);
	}

	switch(e.GetType())
	{
	case MrcEnvelope::EVLP_SEALBOX:
		{
			auto& box = e.GetCredential<MrcCredential_SealedBox>();
			for(UINT i=0; i<box.RecipientCount; i++)
			{
				auto& my_pk = *_Core.GetContacts()->GetPublicKey(myself);
				switch(_Contacts()->GetType(_Recipients[i]))
				{
				case MCT_USER:
					_SetupRecipient(box.Recipients[i], box.Nonce, *master_key, _Recipients[i], my_pk, e.Time);
					break;
				default: ASSERT(0);
				}
			}
		}
		break;
	case MrcEnvelope::EVLP_SEALGREETING:
		{
			ASSERT(_Contacts()->GetType(_Recipients[0]) == MCT_USER);

			auto& my_pk = *_Core.GetContacts()->GetPublicKey(myself);
			auto& g = e.GetCredential<MrcCredential_SealedGreeting>();
			_SetupRecipient(g.Recipient, g.Nonce, *master_key, _Recipients[0], my_pk, e.Time);

			auto& pk = *_Contacts()->GetPublicKey(_Recipients[0]);
			PublicEncryptor(pk).Encrypt(*master_key, (UINT)master_key.size(), g.EncryptedSecret);

			g.ContactPoint.ContactPoint = _GetContactPoint(_Contacts()->GetUserGreetingSecret(_Recipients[0]), sizeof(CipherSecret));
			g.ContactPoint.Reserved = 0;
			g.ContactPoint.Reserved2 = 0;

			_Contacts()->SignOnBehalfOfMe(&g.Signature, master_key, (uint32_t)master_key.size());
		}
		break;
	case MrcEnvelope::EVLP_BROADCAST:
		{
			auto type = _Contacts()->GetType(_Recipients[0]);
			auto& fc = e.GetCredential<MrcCredential_Broadcast>();
			fc.ContactPoint.Reserved = 0;
			fc.ContactPoint.Reserved2 = 0;

			if(type == MCT_COMMUNITY)
			{
				fc.ContactPoint.ContactPoint = _GetContactPoint(_Contacts()->GetPublicKey(_Recipients[0]), sizeof(PublicKey));
			}
			else
			{
				fc.ContactPoint.ContactPoint = _GetContactPoint(_Contacts()->GetPublicKey(myself), sizeof(PublicKey));
			}

			_Contacts()->SignOnBehalfOfMe(&fc.Signature, master_key, (uint32_t)master_key.size());
		}
		break;
	case MrcEnvelope::EVLP_COMMUNITYSEND:
		{
			auto& cc = e.GetCredential<MrcCredential_CommunitySend>();
			_Contacts()->SignOnBehalfOfMe(&cc.Signature, master_key, (uint32_t)master_key.size());
		}
		break;
	default: ASSERT(0);
	}

	ASSERT(_Envelope.GetSize() == _Env()->GetSize());
}

uint8_t MrcMessageAssembler::AddMediaOffloaded(const MrcMediaOffload& offload, const HashValue& org_data_hash)
{
	for(UINT i=0; i<_MediaOffloads.GetSize(); i++)
	{
		if(rt::IsEqual(_MediaOffloads[i].Hash, offload.Hash))
			return (uint8_t)i;
	}

	ASSERT(_MediaOffloads.GetSize() < 255);
	_MediaOffloads.push_back(offload);
	_MediaOffloadSecrets.push_back(org_data_hash);

	return (uint8_t)_MediaOffloads.GetSize() - 1;
}

bool MrcMessageAssembler::SetContent(uint8_t type, const void* data, uint32_t size)
{
	if(data && size > MRC_MESSAGE_CONTENT_MAXSIZE*2)return false;
	if(data == nullptr && size == 0)
	{
		_pContent = nullptr;
		_ContentSize = 0;
		_ContentType = 0;

		return true;
	}

	if(type == MRC_CONTENT_TYPE_UTF8 && size>4)
	{
		auto usize = os::UTF8DecodeLength((LPCSTR)data, size);
		if(usize*2 < size - 4 && usize*2 < MRC_MESSAGE_CONTENT_MAXSIZE)
		{
			VERIFY(_ContentUTF16.ChangeSize(usize));
			os::UTF8Decode((LPCSTR)data, size, _ContentUTF16);
			_ContentSize = usize*2;
			_pContent = _ContentUTF16;
			_ContentType = MRC_CONTENT_TYPE_UTF16;

			return true;
		}
	}

	if(data && size > MRC_MESSAGE_CONTENT_MAXSIZE)return false;
	_pContent = data;
	_ContentSize = size;
	_ContentType = type;

	return true;
}

void MrcMessageAssembler::SetObservatoryData(const void* data, uint32_t size)
{
	_pObservatoryData = data;
	_ObservatoryDataSize = size;
}

MrcPayloadAvailability MrcMessageAssembler::Finalize(MrcPayloadOptions pld_opt)
{
	int pld_avail = 0;
	if(pld_opt&(MPO_OBSERVATORY_REQUIRED|MPO_OBSERVATORY_SUGGESTED))ASSERT(_pObservatoryData);

	// CPLD_CONTENT
	if(_pContent)
	{
		_BeginPayload(MrcCipherPayload::CPLD_CONTENT);
		auto* buf = _AppendPayload(1 + _ContentSize);
		buf[0] = _ContentType;
		memcpy(buf+1, _pContent, _ContentSize);

		_EndPayload();
		pld_avail |= MPA_CONTENT;
	}

	// CPLD_MEDIA_OFFLOADS
	if(_MediaOffloads.GetSize())
	{
		ASSERT(_MediaOffloads.GetSize() < 256);
		ASSERT(_MediaOffloadSecrets.GetSize() == _MediaOffloads.GetSize());

		_BeginPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS, false);
		auto* p = _AppendPayload(_MediaOffloads.GetSize()*sizeof(MrcMediaOffload) + 1);

		// MrcMediaOffloads
		p[0] = (BYTE)_MediaOffloads.GetSize();
		_MediaOffloads.CopyTo((MrcMediaOffload*)(p+1));

		_EndPayload();
		pld_avail |= MPA_MEDIA_OFFLOADS;
	}

	uint32_t size_limit = MRC_MESSAGE_MTU*(_GroupRecipient?2:1);

	// CPLD_ATTACHMENTS
	if(pld_opt || (pld_avail&MPA_MEDIA_OFFLOADS) || _GroupRecipient)
	{
		_BeginPayload(MrcCipherPayload::CPLD_ATTACHMENTS);

		uint16_t atts = 0;
		static_assert(sizeof(atts) == sizeof(MrcMessageAttachmentTypes));

		int size_offload_secrets = 0;
		int size_greeting = 0;
		rt::String_Ref my_name;

		if(_MediaOffloadSecrets.GetSize())
		{
			atts |= MRCATT_OFFLOAD_SECRETS;
			size_offload_secrets = _MediaOffloadSecrets.GetSize()*sizeof(HashValue) + 1;
		}

		auto myself = _Contacts()->GetMyself();
		MrcContactProfile my_profile;

		if(	(pld_opt&(MPO_GREETING_REQUIRED|MPO_GREETING_SUGGESTED)) || 
			_Env()->GetType() == MrcEnvelope::EVLP_SEALGREETING || 
			_Env()->GetType() == MrcEnvelope::EVLP_COMMUNITYSEND || 
			(_Recipients[0] && _Contacts()->GetType(_Recipients[0]) == MCT_COMMUNITY)
		)
		{
			VERIFY(_Contacts()->GetProfile(myself, &my_profile));

			if(_Env()->GetType() != MrcEnvelope::EVLP_COMMUNITYSEND)
			{
				my_name = my_profile.Name.SubStrHead(MRC_PROFILE_NAME_SIZEMAX);
				size_greeting = offsetof(MrcAttachmentGreeting, NameBuf) + (int)my_name.GetLength();
			}
			else
				size_greeting = offsetof(MrcAttachmentGreeting, Gender);
		}

		// composing attachments
		uint32_t MrcMessageAttachmentTypes_Offset;
		{
			auto* p = _AppendPayload(sizeof(WORD)); // for MrcMessageAttachmentTypes
			MrcMessageAttachmentTypes_Offset = (uint32_t)(p - _Envelope.Begin());
		}

		int size_avail = (int)size_limit - (int)_Envelope.GetSize() - size_offload_secrets;
		if(_pObservatoryData && (pld_opt&MPO_OBSERVATORY_REQUIRED))size_avail -= _ObservatoryDataSize;

		// MRCATT_TINYGROUP_INFO
		if(_GroupRecipient)
		{
			atts |= MRCATT_TINYGROUP_INFO;

			auto* ginfo = (MrcAttachmentTinyGroupInfo*)_AppendPayload(sizeof(MrcAttachmentTinyGroupInfo));
			ASSERT(ginfo);

			UINT composed_size;
			MrcGroupInfo info;
			VERIFY(_Contacts()->GetGroupInfo(_GroupRecipient, &info));

			if(_GroupInfo.MemberCount == info.MemberCount)
			{
				int max_size = size_avail - offsetof(MrcAttachmentTinyGroupInfo, InfoBlocks);
				if(MPO_GREETING_REQUIRED&pld_opt)max_size -= size_greeting;
				if(MPO_ACCESSPOINTS_REQUIRED&pld_opt)max_size -= 200;

				auto type = MrcAttachmentTinyGroupInfo::DetermineComposeFields(_Contacts(), _GroupRecipient, _GroupInfo, _GroupMembers, max_size);
				composed_size = ginfo->Compose(_Contacts(), _GroupRecipient, _GroupInfo, _GroupMembers, type);
			}
			else // just involved
			{
				composed_size = ginfo->Compose(_Contacts(), _GroupRecipient, _GroupInfo, _GroupMembers);
			}

			_TrimAppendedPayload(sizeof(MrcAttachmentTinyGroupInfo) - composed_size);
			size_avail -= composed_size;
		}

		// MRCATT_GREETING
		if(	(pld_opt&MPO_GREETING_REQUIRED) || 
			((pld_opt&MPO_GREETING_SUGGESTED) && size_avail >= size_greeting)
		)
		{
			atts |= MRCATT_GREETING;
			ASSERT(size_greeting);

			auto* greeting = (MrcAttachmentGreeting*)_AppendPayload(size_greeting);

			greeting->Sender = *_Contacts()->GetPublicKey(myself);
			greeting->Size = size_greeting;
			greeting->PublicData = *my_profile.PublicData;
			greeting->SocialPreference = my_profile.SocialPreference;

			if(size_greeting > offsetof(MrcAttachmentGreeting, Location))
			{
				greeting->Gender =  my_profile.Gender;
				greeting->Location =  my_profile.Location;
				my_name.CopyTo(greeting->NameBuf);
			}

			size_avail -= size_greeting;
			pld_avail |= MPA_GREETING;
		}

		// MRCATT_OFFLOAD_SECRETS
		if(atts&MRCATT_OFFLOAD_SECRETS)
		{
			auto* dst = (MrcAttachmentMediaOffloadSecrets*)_AppendPayload(size_offload_secrets);
			_MediaOffloadSecrets.CopyTo(dst->Secrets);
			dst->Count = _MediaOffloadSecrets.GetSize();
		}

		// MRCATT_ACCESS_POINTS
		if(	(pld_opt&MPO_ACCESSPOINTS_REQUIRED) || 
			((pld_opt&MPO_ACCESSPOINTS_SUGGESTED) && size_avail > 64)
		)
		{
			auto* aps = (MrcAttachmentAccessPoints*)_AppendPayload(sizeof(MrcAttachmentAccessPoints));
			if(_Core.GetAccessPoints(aps->APS, size_avail - sizeof(DhtAddress)))
			{
				atts |= MRCATT_ACCESS_POINTS;
				aps->DeviceId = _Core.GetLocalNodeDeviceId();
				_TrimAppendedPayload(sizeof(MrcAttachmentAccessPoints) - aps->GetSize());

				pld_avail |= MPA_ACCESSPOINTS;
			}
			else
			{	
				_TrimAppendedPayload(sizeof(MrcAttachmentAccessPoints));
			}
		}

		// finalize MrcMessageAttachmentTypes
		*(uint16_t*)(((char*)_Env()) + MrcMessageAttachmentTypes_Offset) = atts;

		_EndPayload();
	}

	// CPLD_OBSERVATORY
	if(	_pObservatoryData && _ObservatoryDataSize &&
		(	(pld_opt&MPO_OBSERVATORY_REQUIRED) ||
			(size_limit >= GetEnvelopeSize() + _ObservatoryDataSize)
		)
	)
	{
		_BeginPayload(MrcCipherPayload::CPLD_OBSERVATORY, false);
		memcpy(_AppendPayload(_ObservatoryDataSize), _pObservatoryData, _ObservatoryDataSize);
		_EndPayload();
		pld_avail |= MPA_OBSERVATORY;
	}

	_MediaOffloads.ShrinkSize(0);
	_MediaOffloadSecrets.ShrinkSize(0);

	_Seal();
	return (MrcPayloadAvailability)pld_avail;
}

} // namespace upw