#pragma once
#include "mrc_message.h"


namespace upw
{

class MessageRelayCore;
struct MrcRecipient;

enum MrcPayloadOptions
{
	// Input
	MPO_NONE					= 0,
	MPO_GREETING_REQUIRED		= (1<<1),
	MPO_ACCESSPOINTS_REQUIRED	= (1<<2),
	MPO_OBSERVATORY_REQUIRED	= (1<<3),

	MPO_GREETING_SUGGESTED		= MPO_GREETING_REQUIRED<<16,
	MPO_ACCESSPOINTS_SUGGESTED	= MPO_ACCESSPOINTS_REQUIRED<<16,
	MPO_OBSERVATORY_SUGGESTED	= MPO_OBSERVATORY_REQUIRED<<16
};

enum MrcPayloadAvailability
{
	MPA_NONE					= 0,
	MPA_CONTENT					= (1<<0),
	MPA_MEDIA_OFFLOADS			= (1<<1),
	MPA_GREETING				= (1<<2),
	MPA_TINYGROUP				= (1<<3),
	MPA_ACCESSPOINTS			= (1<<4),
	MPA_OBSERVATORY				= (1<<5),
};

class MrcMessageAssembler
{
protected:
	MessageRelayCore&	_Core;

	UINT				_PayloadStartOffset;
	MrcContact			_Recipients[MRC_MESSAGE_RECIPENTS_MAX];
	const MrcContact*	_AdditionalRecipients = nullptr;  // for sealbox only
	UINT				_AdditionalRecipientCount = 0;

	bool				_bIsCommunityCast = false;

	MrcContact			_GroupRecipient = 0;
	MrcGroupInfo		_GroupInfo;
	MrcGroupMember		_GroupMembers[MRC_MESSAGE_RECIPENTS_MAX];

	auto				_Contacts() const -> MrcContactsRepository*;
	MrcContactPointNum	_GetContactPoint(LPCVOID data, UINT size) const;
	void				_SetupRecipient(MrcRecipient& r, const NonceData& nonce, const CipherSecret& key, MrcContact recipent, const PublicKey& my_pk, const NetTimestamp& time);

	rt::BufferEx<BYTE>	_Envelope;
	UINT				_PayloadOffset;
	auto*				_Env(){ return (MrcEnvelope*)_Envelope.Begin(); }
	auto*				_Env() const { return (const MrcEnvelope*)_Envelope.Begin(); }
	auto*				_Pld(){ ASSERT(_PayloadStartOffset); return (MrcCipherPayload*)&_Envelope[_PayloadStartOffset]; }

	void				_Init(MrcAppId app, WORD action, uint64_t ts, bool recipients_inited = false);
	void				_InitBroadcast(MrcAppId app, WORD action, uint64_t ts, bool recipients_inited = false);
	bool				_AllocateSealedBox(UINT count);

	void				_BeginPayload(MrcCipherPayload::Type pld_type, bool encrypted = true);
	LPBYTE				_AppendPayload(UINT size);
	void				_TrimAppendedPayload(UINT size);
	void				_EndPayload();
	void				_Seal();

public:
	MrcMessageAssembler(MessageRelayCore& x);
	void				SetAdditionalRecipients(const MrcContact* reps, uint32_t co);  // call before creat
	bool				Create(MrcContact recipient, MrcAppId app, WORD action, uint64_t ts);
	bool				Create(const MrcContact* recipient, UINT count, MrcAppId app, WORD action, uint64_t ts);  // for EVLP_SEALBOX 1:n, n=1 to 10 (SOCIAL_MESSAGE_RECIPENTS_MAX)
	bool				CreateFollowerCast(MrcAppId app, WORD action, uint64_t ts); // EVLP_BROADCAST 1:all
	bool				CreateCommunityCast(MrcContact recipient, MrcAppId app, WORD action, uint64_t ts);
	auto				GetSealed() const { return (MrcEnvelope*)rt::_CastToNonconst(this)->_Env(); }
	UINT				GetSealedSize() const { return _Envelope.GetSize(); }
	bool				IsCommunitySend() const { return _Env()->GetType() == MrcEnvelope::EVLP_COMMUNITYSEND; }
	bool				IsBroadcast() const { return _Env()->GetType() == MrcEnvelope::EVLP_BROADCAST; }
	bool				IsSealGreeting() const { return _Env()->GetType() == MrcEnvelope::EVLP_SEALGREETING;	}
	bool				IsGroupMessage() const { return _GroupRecipient; }
	bool				IsSignatureRequired() const { return IsCommunitySend() || IsBroadcast(); }
	bool				IsCommunityCast() const { return _bIsCommunityCast; }

protected:
	rt::BufferEx<MrcMediaOffload>	_MediaOffloads;		// in public payload
	rt::BufferEx<HashValue>			_MediaOffloadSecrets;	// in private attachments

	const void*						_pContent = nullptr;
	uint32_t						_ContentSize = 0;
	uint8_t							_ContentType = 0;
	rt::BufferEm<os::U16CHAR, 129>	_ContentUTF16;

	const void*						_pObservatoryData = nullptr;
	uint32_t						_ObservatoryDataSize = 0;

public:
	bool			SetContent(uint8_t type, const void* data, uint32_t size);
	uint8_t			AddMediaOffloaded(const MrcMediaOffload& offload, const HashValue& org_data_hash); // return offload index
	uint8_t			AddMediaOffloaded(const MrcMediaOffloadItem& item){ return AddMediaOffloaded(item, item.SecretHash); }
	void			SetObservatoryData(const void* data, uint32_t size);
	void			SetTimestamp(LONGLONG ts){ _Env()->Time = ts; }

	auto			Finalize(MrcPayloadOptions atts_opt = MPO_NONE) -> MrcPayloadAvailability;

	uint32_t		GetEnvelopeSize() const { return _Envelope.GetSize(); }
	operator const	MrcEnvelope* () const { return _Env(); }
	operator const	MrcEnvelope& () const { return *_Env(); }
};

} // namespace upw