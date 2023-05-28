#include "mrc.h"
#include "mrc_dissemble.h"
#include "mrc_attachments.h"
#include "mrc_credential.h"
#include "../netsvc_core.h"


namespace upw
{

bool MrcMessageDisassembler::IsSentByOtherUser() const 
{
	return _bDecrypted && !_bSentByMe && _PeerMain && _Contacts()->GetType(_PeerMain) == MCT_USER;
}

MrcContactsRepository* MrcMessageDisassembler::_Contacts() const 
{
	return rt::_CastToNonconst(_Core.GetContacts()); 
}

void MrcMessageDisassembler::Clear()
{
	for(UINT i=0; i<MrcCipherPayload::CPLD_TYPE_MAX; i++)
		_PayloadDecipheredData[i].ShrinkSize(0);

	rt::Zero(_Payload);
	rt::Zero(_MasterKey);
	_pRecipients = nullptr;
	_bDecrypted = false;
	_PeerMain = 0;
	_GroupContact = 0;
	_RecipientCount = 0;
	rt::Zero(_pResolvedRecipients);

	_pTinyGroupInfo = nullptr;
	_pGreeting = nullptr;
	_pMediaOffloadSecrets = nullptr;
	_pAccessPoints = nullptr;
	_bDecrypted = false;
}

void MrcMessageDisassembler::_ComputePayloadHash(const MrcEnvelope* env, HashValue& key) const
{
	auto& h = GetHasher();
	bool has_nonce = env->HasNonce();
	if(has_nonce)
		h.Update(env->GetNonce());
	else
	{
		h.Update(env->Time);
		if(_Type == MrcEnvelope::EVLP_COMMUNITYSEND)
			h.Update(*_Contacts()->GetPublicKey(_PeerMain));
	}

	uint32_t iter;
	auto* pld = env->GetFirstPayload(iter);
	
	if(has_nonce)
		while(pld)
		{	// decrypted data is on _Payload
			auto* decip = _Payload[pld->GetType()];
			ASSERT(decip);
			h.Update(decip->Data, decip->GetOriginalDataSize());

			pld = env->GetNextPayload(pld, iter);
		}
	else
		while(pld)
		{
			if(pld->IsEncrypted())
				h.Update(pld->Data, pld->GetDataSize());
			else
				h.Update(pld->Data, pld->GetOriginalDataSize());

			pld = env->GetNextPayload(pld, iter);
		}

	h.Update(env, offsetof(MrcEnvelope, CredentialData));
	h.Finalize(&key);
}

bool MrcMessageDisassembler::_LoadPayloads(const MrcEnvelope* env)
{
	Cipher dec(_MasterKey);

	uint32_t iter;
	auto* pld = env->GetFirstPayload(iter);
	while(pld)
	{
		if(_Payload[pld->GetType()])return false;  // duplicated

		MrcCipherPayload* decip = (MrcCipherPayload*)pld;
		if(pld->IsEncrypted())
		{
			auto& buf = _PayloadDecipheredData[pld->GetType()];
			VERIFY(buf.SetSize(pld->GetSize()));
			decip = (MrcCipherPayload*)buf.Begin();
			*decip = *pld;

			dec.Decode((LPVOID)pld->Data, decip->Data, pld->GetDataSize(), pld->GetNonce());
		}

		_Payload[pld->GetType()] = decip;
		pld = env->GetNextPayload(pld, iter);
	}

	return true;
}

MrcContact MrcMessageDisassembler::_UnsealRecipient(const MrcRecipient& r, const MrcEnvelope& env, bool ignore_relationship)
{
	MrcContact ret = _Core.GetContactsControl().ResolveRecipient(r.ContactPoint, env.Time);
	auto type = _Contacts()->GetType(ret);
	if(type != MCT_USER)return 0;

	if(!ignore_relationship)
	{
		auto relation = _Contacts()->GetRelationship(ret);
		if((relation&MCR_KNOWN) == 0)
			return 0;
	}

	if(_Contacts()->DecryptKeyFromUser(ret, &env.GetNonce(), &r.SealedSecret, &_MasterKey))
	{
		_bSentByMe = r.IsSendingUp() == (*_Contacts()->GetPublicKey(_Contacts()->GetMyself()) < *_Contacts()->GetPublicKey(ret));
		if (!_bSentByMe)
			_bSentByMe = (*_Contacts()->GetPublicKey(ret) == *_Contacts()->GetPublicKey(_Contacts()->GetMyself()));
		return ret;
	}

	return 0;
}

void MrcMessageDisassembler::ReplaceContentPayload(const void* data, uint32_t size, uint8_t mime)
{
	auto& buf = _PayloadDecipheredData[MrcCipherPayload::CPLD_CONTENT];

	buf.ChangeSize(1ULL + size + offsetof(MrcCipherPayload, Data));
	auto& pld = *(MrcCipherPayload*)buf.Begin();

	pld.Data[0] = mime;
	memcpy(pld.Data + 1, data, size);
	pld.Payload_Padding = MrcCipherPayload::CPLD_CONTENT | (((size + 1)%Cipher::DataBlockSize)<<4);
	pld.EncBit_BlockCount = (size + 1)/Cipher::DataBlockSize;

	_Payload[MrcCipherPayload::CPLD_CONTENT] = &pld;
}

bool MrcMessageDisassembler::_DecryptAll(const MrcEnvelope* env)
{
	if(env->HasNonce())
	{
		if(!_LoadPayloads(env))return false;
		_ComputePayloadHash(env, _PayloadHash); // master key is over raw data after decryption

		static_assert(sizeof(CipherSecret) == sizeof(HashValue), "size of ContactAddress and CipherSecret should match");
		if(!rt::IsEqual<sizeof(HashValue)>(&_PayloadHash, &_MasterKey))
			return false;
	}
	else
	{
		_ComputePayloadHash(env, _PayloadHash); // hash is over encrypted data
		if(!_LoadPayloads(env))return false;
	}

	if(HasPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS))
	{
		auto& payload = GetPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS);
		if(payload.Data[0]*sizeof(MrcMediaOffload) + 1 != payload.GetOriginalDataSize())
			return false;

		uint32_t minute_max = env->Time/(60*1000);

		for(uint32_t i=0; i<payload.Data[0]; i++)
		{
			auto& d = ((MrcMediaOffload*)&payload.Data[1])[i];
			if(d.Size <= d.Padding)return false;
			if(d.MinuteStamp > minute_max)return false;
		}
	}

	if (HasPayload(MrcCipherPayload::CPLD_CONTENT))
	{
		auto& payload = GetPayload(MrcCipherPayload::CPLD_CONTENT);
		if (payload.Data[0] == MRC_CONTENT_TYPE_UTF16)
		{
			auto* utf16 = (os::LPCU16CHAR)(payload.Data + 1);
			auto utf16_len = (payload.GetOriginalDataSize() - 1) / 2;

			auto utf8_len = os::UTF8EncodeLength(utf16, utf16_len);
			rt::BufferEm<char, 64> str;
			str.SetSize(utf8_len);

			os::UTF8Encode(utf16, utf16_len, str.Begin());
			ReplaceContentPayload(str.Begin(), str.GetSize(), MRC_CONTENT_TYPE_UTF8);
		}
	}

	// load all attachments
	if(!HasPayload(MrcCipherPayload::CPLD_ATTACHMENTS))return true;
	auto& payload = GetPayload(MrcCipherPayload::CPLD_ATTACHMENTS);
	auto AttachmentBits = *(MrcMessageAttachmentTypes*)payload.Data;

	LPCBYTE p = &payload.Data[sizeof(MrcMessageAttachmentTypes)];
	LPCBYTE end = payload.Data + payload.GetOriginalDataSize();

#define PICK_ATTACHMENT_SIZED(type, var)	\
	if(type & AttachmentBits)				\
	{	var = (decltype(var))p;				\
		UINT sz = var->GetSize();			\
		if(sz == 0)return false;			\
		p += sz;							\
		if(p>end)return false;				\
	}

	PICK_ATTACHMENT_SIZED(MRCATT_TINYGROUP_INFO,	_pTinyGroupInfo)
	PICK_ATTACHMENT_SIZED(MRCATT_GREETING,			_pGreeting)

	PICK_ATTACHMENT_SIZED(MRCATT_OFFLOAD_SECRETS,	_pMediaOffloadSecrets)
	PICK_ATTACHMENT_SIZED(MRCATT_ACCESS_POINTS,		_pAccessPoints)

#undef PICK_ATTACHMENT_SIZED

	_bDecrypted = true;
	return true;
}

void MrcMessageDisassembler::ResolveAllRecipients()
{
	ASSERT(_bDecrypted && _bSentByMe);

	if(_pEnvelope->GetType() != MrcEnvelope::EVLP_SEALGREETING)
	{
		ASSERT(_pEnvelope->GetType() == MrcEnvelope::EVLP_SEALBOX);

		auto& box = _pEnvelope->GetCredential<MrcCredential_SealedBox>();
		for(UINT i=_PeerMainIdx+1; i<box.RecipientCount; i++)
			_pResolvedRecipients[i] = _UnsealRecipient(box.Recipients[i], *_pEnvelope, false);
	}
}

bool MrcMessageDisassembler::Unseal(const MrcEnvelope* env, MrcRecvContext& ctx)
{
	_bSentByMe = false;
	bool SignatureVerifyRequiredForSealedGreeting = false;
	Clear();

	auto myself = _Contacts()->GetMyself();

	_pEnvelope = env;
	_Type = env->GetType();
	switch(_Type)
	{
	case MrcEnvelope::EVLP_SEALBOX:
		{
			auto& box = env->GetCredential<MrcCredential_SealedBox>();
			for(UINT i=0; i<box.RecipientCount; i++)
			{
				_pResolvedRecipients[i] = _UnsealRecipient(box.Recipients[i], *env, false);
				if(_pResolvedRecipients[i] && !_PeerMain)
				{
					_PeerMain = _pResolvedRecipients[i];
					_PeerMainIdx = i;
					_pRecipients = box.Recipients;
					_RecipientCount = box.RecipientCount;
					if(!_DecryptAll(env)){ Clear(); return false; }

					_bDecrypted = true;

					if(box.RecipientCount == 1 && !ctx.Conversation)
						ctx.Conversation = _pResolvedRecipients[i];

					return true;
				}
			}
			return  false;
		}
		break;
	case MrcEnvelope::EVLP_SEALGREETING:
		{	
			auto& g = env->GetCredential<MrcCredential_SealedGreeting>();
			_PeerMain = _UnsealRecipient(g.Recipient, *env, true);
			if(_PeerMain)
			{
				_pResolvedRecipients[0] = _PeerMain;
				if(!ctx.Conversation)
					ctx.Conversation = _PeerMain;
			}
			else
			{	// if not friended, try greeting
				MrcContact ret = _Core.GetContactsControl().ResolveRecipient(g.ContactPoint.ContactPoint, env->Time);
				if (!ret)return false;

				auto type = _Contacts()->GetType(ret);
				if (type != MCT_USER_GREETING && type != MCT_COMMUNITY)return false;
				if (!_Contacts()->DecryptAnonymousDataToMe(g.EncryptedSecret, sizeof(EncryptedCipherSecret), _MasterKey))
					return false;

				ctx.Conversation = 0;
			}
				
			_pRecipients = &g.Recipient;
			_RecipientCount = 1;

			if(	!_DecryptAll(env) || 
				!_pGreeting || 
				!_pGreeting->Sender.Verify(g.Signature, &_MasterKey, sizeof(_MasterKey))
			)
			{	Clear();
				return false;
			}

			_bDecrypted = true;			
			return true;
		}
		break;
	case MrcEnvelope::EVLP_BROADCAST:
		{
			static_assert(sizeof(CipherSecret) == sizeof(PublicKey), "size of ContactAddress and CipherSecret should match");

			auto& fc = env->GetCredential<MrcCredential_Broadcast>();
			_PeerMain = _Core.GetContactsControl().ResolveRecipient(fc.ContactPoint.ContactPoint, env->Time);
			if (!_PeerMain)
			{
				// to JP : more checks?
				return false;
			}

			if(!ctx.Conversation)
				ctx.Conversation = _PeerMain;

			_pRecipients = nullptr;
			_RecipientCount = 0;
			bool is_community = _Contacts()->GetType(_PeerMain) == MCT_COMMUNITY;

			if(is_community)
				_MasterKey = *_Contacts()->GetSecret(_PeerMain);
			else
				_MasterKey = *(CipherSecret*)_Contacts()->GetPublicKey(_PeerMain);
			
			if(is_community)
			{
				if(	!_DecryptAll(env) ||
					!_pGreeting ||
					!_pGreeting->Sender.Verify(fc.Signature, &_PayloadHash, sizeof(_PayloadHash))
				)
				{	Clear();
					return false;
				}

				_bSentByMe = _pGreeting->Sender == *_Contacts()->GetPublicKey(myself);
			}
			else
			{
				if(	!_DecryptAll(env) || 
					!_Contacts()->VerifySignature(_PeerMain, &_PayloadHash, sizeof(_PayloadHash), &fc.Signature)
				)
				{	Clear();
					return false;
				}

				_bSentByMe = _Contacts()->IsMyself(_PeerMain);
			}

			_bDecrypted = true;
			return true;
		}
		break;
	case MrcEnvelope::EVLP_COMMUNITYSEND:
		{
			if(!ctx.Conversation) return false;
			ASSERT(_Contacts()->GetType(ctx.Conversation) == MCT_COMMUNITY);
			
			_PeerMain = ctx.Conversation;
			_pRecipients = nullptr;
			_RecipientCount = 0;
			_MasterKey = *_Contacts()->GetSecret(ctx.Conversation);

			auto& cs = env->GetCredential<MrcCredential_CommunitySend>();
			if(	!_DecryptAll(env) ||
				!_pGreeting ||
				!_pGreeting->Sender.Verify(cs.Signature, &_PayloadHash, sizeof(_PayloadHash))
			)
			{	Clear();
				return false;
			}

			_bSentByMe = *_Contacts()->GetPublicKey(myself) == _pGreeting->Sender;
			return true;
		}
		break;
	}

	return false;
}

bool MrcMessageDisassembler::HandleControlMessage(MrcRecvContext& ctx)
{
	if(_Core._ContactsControl.HandleControlMessage(*this, ctx))
	{
		if(_Core.Net()->HasAPI())
		{
			_Core._ApiMessageReceived(*this, ctx);
		}

		return true;
	}

	return false;
}

} // namespace upw
