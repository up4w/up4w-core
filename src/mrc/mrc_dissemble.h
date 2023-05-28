#pragma once
#include "mrc_message.h"


namespace upw
{

class MessageRelayCore;
struct MrcRecipient;
struct MrcAttachmentGreeting;
struct MrcAttachmentAccessPoints;
struct MrcAttachmentTinyGroupInfo;
struct MrcAttachmentMediaOffloadSecrets;

class MrcMessageDisassembler
{
	friend class MrcContactsControl;

protected:
	MessageRelayCore&				_Core;
	MrcContactsRepository*			_Contacts() const;

	bool							_bDecrypted;
	const MrcEnvelope*				_pEnvelope = nullptr;
	MrcContact						_PeerMain = 0;
	uint32_t						_PeerMainIdx = MRC_MESSAGE_RECIPENTS_MAX;
	MrcContact						_GroupContact = 0;
	CipherSecret					_MasterKey;
	bool							_bSentByMe = false;
	const MrcRecipient*				_pRecipients;
	UINT							_RecipientCount;
	MrcContact						_pResolvedRecipients[MRC_MESSAGE_RECIPENTS_MAX]; // for SealBox only
	MrcEnvelope::CredentialType		_Type;

	HashValue						_PayloadHash;
	rt::BufferEx<BYTE>				_PayloadDecipheredData[MrcCipherPayload::CPLD_TYPE_MAX];
	const MrcCipherPayload*			_Payload[MrcCipherPayload::CPLD_TYPE_MAX];

	const MrcAttachmentTinyGroupInfo*		_pTinyGroupInfo = nullptr;
	const MrcAttachmentGreeting*			_pGreeting = nullptr;
	const MrcAttachmentMediaOffloadSecrets*	_pMediaOffloadSecrets = nullptr;	// align with ones in MrcMediaOffloads
	const MrcAttachmentAccessPoints*		_pAccessPoints = nullptr;

	bool			_DecryptAll(const MrcEnvelope* env);
	void			_ComputePayloadHash(const MrcEnvelope* env, HashValue& key) const;
	bool			_LoadPayloads(const MrcEnvelope* env); // decryption, assume _MasterKey is available
	MrcContact		_UnsealRecipient(const MrcRecipient& r, const MrcEnvelope& env, bool ignore_relationship); // will update _MasterKey and _bSentByMe

public:
	MrcMessageDisassembler(MessageRelayCore& x):_Core(x){}
	~MrcMessageDisassembler(){ Clear(); }

	bool	Unseal(const MrcEnvelope* env, MrcRecvContext& ctx);  // ctx.Conversation will be set, if yet set
	auto&	GetPayload(MrcCipherPayload::Type type) const { ASSERT(HasPayload(type)); return *_Payload[type]; }
	bool	HasPayload(MrcCipherPayload::Type type) const { return _Payload[type]; }
	auto&	GetEnvelope() const { return *_pEnvelope; }
	bool	HandleControlMessage(MrcRecvContext& ctx); // ctx.Conversation will be set, if yet set
	bool	IsMasterKeyDecrypted() const { return _bDecrypted; }
	auto	GetPeer() const { return _PeerMain; }

	bool	IsGroupMessage() const { return _pTinyGroupInfo && MrcEnvelope::EVLP_SEALBOX == _Type; }
	auto	GetGroupContact() const { ASSERT(_GroupContact); return _GroupContact; }
	auto	GetPeerContact() const { ASSERT(_PeerMain); return _PeerMain; }
	bool	IsSentByMe() const { return _bDecrypted && _bSentByMe; }
	bool	IsSentByOtherUser() const;
	bool	HasPeerContact() const { return _PeerMain; }
	auto*	GetMediaOffloads() const { auto* ret = _Payload[MrcCipherPayload::CPLD_MEDIA_OFFLOADS]; return ret?(const MrcMediaOffloads*)ret->Data:nullptr; }
	void	ReplaceContentPayload(const void* data, uint32_t size, uint8_t mime = 1);
	auto*	GetAttachmentGreeting() const { return _pGreeting; }

	UINT	GetRecipientCount() const { return _RecipientCount; }
	auto*	GetRecipients() const { return _bDecrypted?(const MrcContact*)_pResolvedRecipients:nullptr; }
	void	ResolveAllRecipients(); // only for sealbox, IsMasterKeyDecrypted() and sent by me
	auto	GetType() const { return _Type; }
	void	Clear();
};

} // namespace upw