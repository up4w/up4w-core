#include "mrc.h"
#include "../api/local_api.h"
#include "../netsvc_core.h"
#include "../swarm_broadcast.h"
#include "mrc_contacts.h"
#include "mrc_message.h"
#include "mrc_dissemble.h"
#include "mrc_assemble.h"
#include "mrc_attachments.h"
#include "mrc_media_core.h"


namespace upw
{

void MessageRelayCore::_ApiMessageJsonify(rt::Json& json, const MrcMessageDisassembler& msg, const MrcRecvContext& ctx) const
{
	auto& evn = msg.GetEnvelope();
	json.Object((
		J(id) = rt::tos::Number(ctx.MsgHash),
		J(timestamp) = (int64_t)evn.Time,
		J(app) = evn.App,
		J(action) = evn.Action,
		J_IF(ctx.Conversation, J(recipient) = tos_base32(*GetContacts()->GetPublicKey(ctx.Conversation)))
	));

	{	rt::SS sz_sender = "sender";

		if(msg.IsSentByMe())
			json.AppendKey(sz_sender, rt::SS(":myself"));
		else
		{
			auto mc = msg.GetPeer();
			if(mc)
				json.AppendKey(sz_sender, tos_base32(*GetContacts()->GetPublicKey(msg.GetPeer())));
			else
				json.AppendKey(sz_sender, rt::SS(":anonymous"));
		}
	}

	if(msg.HasPayload(MrcCipherPayload::CPLD_CONTENT))
	{
		auto& pld = msg.GetPayload(MrcCipherPayload::CPLD_CONTENT);
		auto& content = *(MrcCipherPayload::Content*)pld.Data;
		rt::SS sz_content = "content";
		switch(content.Type)
		{
		case MRC_CONTENT_TYPE_UTF8:
			json.AppendKeyWithString(sz_content, rt::DS(content.Data, pld.GetOriginalDataSize() - 1));
			break;
		default:
			json.AppendKeyWithBinary(sz_content, rt::DS(content.Data, pld.GetOriginalDataSize() - 1));
		}

		json.AppendKey("content_type", content.Type);
	}

	{	auto* g = msg.GetAttachmentGreeting();
		if(g)
		{
			auto m = json.ScopeAppendingKey("greeting");
			json.Object((
				J(sender) = tos_base32(g->Sender),
				J_IF(
					g->HasProfileIntro(), 
					J(profile) = (
						J(name) = rt::JsonEscapeString(g->GetName()),
						J(gender) = g->Gender,
						J(geolocation) = g->Location
					)
			)));
		}
	}

	if(msg.HasPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS))
	{
		auto& pld = msg.GetPayload(MrcCipherPayload::CPLD_MEDIA_OFFLOADS);
		auto& offloads = *(MrcMediaOffloads*)pld.Data;

		auto m = json.ScopeAppendingKey("media");
		json.Array();
		for(uint32_t i=0; i<offloads.Count; i++)
		{
			json.AppendElement(rt::tos::Base64OnStack(offloads.Entries[i].Hash));
		}
	}
}

void MessageRelayCore::_ApiMessageReceived(const MrcMessageDisassembler& msg, const MrcRecvContext& ctx)
{
	ASSERT(_pNetCore->HasAPI());
	{
		uint32_t  push_count = 0;
		uint32_t* push;
		{
			auto* pk = _ContactsControl.GetContacts()->GetPublicKey(ctx.Conversation);

			THREADSAFEMUTABLE_SCOPE(_ApiMessageTopics);
			auto& topics = _ApiMessageTopics.GetImmutable();

			push = (uint32_t*)alloca(sizeof(uint32_t)*topics.GetSize());
			for(auto& t : topics)
			{
				if(t.IsMatch(msg.GetEnvelope(), pk))
					push[push_count++] = t.PushTopicIndex;
			}
		}

		if(push_count)
		{
			auto& composer = LocalApiResponder::_ThreadLocalComposer();
			composer.Compose("msg.received");
			_ApiMessageJsonify(composer.ScopeReturnBegin(), msg, ctx);
			composer.ScopeReturnEnd();

			for(uint32_t i=0; i<push_count; i++)
				_pNetCore->API().PushJsonResponse(push[i], composer.GetJsonString());
		}
	}
}

bool MessageRelayCore::ApiMessagePushSelect::operator == (const ApiMessagePushSelect& x) const
{
	if(Flag != x.Flag)return false;
	if((Flag&MPS_APP) && App != x.App)return false;
	if((Flag&MPS_CONVERSATION) && Conversation != x.Conversation)return false;

	return true;
}

bool MessageRelayCore::ApiMessagePushSelect::IsMatch(const MrcEnvelope& msg, const PublicKey* conversation) const
{
	if(Flag == 0)return true;

	if((Flag&MPS_APP) && App != msg.App)return false;
	if((Flag&MPS_CONVERSATION) && (!conversation || Conversation != *conversation))return false;

	return true;
}

bool MessageRelayCore::OnApiInvoke(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp)
{
	if(resp->GetRequest().StartsWith("social."))
		return _ApiInvokeSocial(action, arguments, resp);
	else
	if(resp->GetRequest().StartsWith("msg."))
		return _ApiInvokeMsg(action, arguments, resp);

	return false;
}

MrcContactsRepository* MessageRelayCore::_ApiContacts()
{
	if(_ContactsControl._pContacts == nullptr)
		_ContactsControl._pContacts = _New(MrcContacts(*this));

	return _ContactsControl._pContacts;
}

bool MessageRelayCore::_ApiInvokeSocial(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp)
{
	if(action == rt::SS("signin"))
	{
		rt::JsonObject arg(arguments);
		rt::String_Ref seed = arg.GetValue("seed");
		rt::String_Ref mnemonic = arg.GetValue("mnemonic");

		if(seed.IsEmpty() && mnemonic.IsEmpty())
		{
			resp->SendError(110);
			return true;
		}

		MrcRootSecretSeed secret;
		if(!mnemonic.IsEmpty())
		{
			if(!MnemonicDecode(mnemonic, &secret, secret.EffectiveLength))
			{
				resp->SendError(111);
				return true;
			}
		}
		else
		{
			if(!secret.FromString(seed))
			{
				resp->SendError(111);
				return true;
			}
		}

		auto* cc = _ApiContacts();
		MrcContactProfile profile;
		{
			rt::Zero(profile);
			rt::JsonObject p = arg.GetValue("profile");

			profile.Name = p.GetValue("name");
			profile.Gender = p.GetValueAs<uint8_t>("gender");
			profile.Location = p.GetValueAs<uint16_t>("geolocation");
		}

		if(!_ContactsControl._pContacts->SetMyself(&secret, &profile))
			resp->SendError(112);

		auto mc = cc->GetMyself();
		resp->SendJsonReturnBegin().Object((
			J(pk) = tos_base32(*cc->GetPublicKey(mc))
		));
		resp->SendJsonReturnEnd();
		return true;
	}
	else if(action == rt::SS("add_user") || action == rt::SS("remove_user"))
	{
		auto* cc = _ApiContacts();
		if(cc->GetMyself() == 0)
		{
			resp->SendError(117);
			return true;
		}

		rt::JsonObject arg(arguments);
		rt::String_Ref id = arg.GetValue("pk");
		if(id.IsEmpty())
		{
			resp->SendError(105, "pk");
			return true;
		}

		PublicKey pk;
		if(!pk.FromString(arg.GetValue("pk")))
		{
			resp->SendError(109, "pk");
			return true;
		}

		if(action == rt::SS("add_user"))
		{
			MrcContactProfile profile;
			{
				rt::Zero(profile);
				profile.Address = &pk;
				profile.Name = arg.GetValue("name");
				profile.Gender = arg.GetValueAs<uint8_t>("gender");
				profile.Location = arg.GetValueAs<uint16_t>("geolocation");
			}

			rt::String_Ref greeting = arg.GetValue("greeting_secret");
			if(!greeting.IsEmpty())
			{
				CipherSecret s;
				if(!s.FromString(greeting))
				{
					resp->SendError(114, "greeting_secret");
					return true;
				}

				cc->CreateUser(&profile, true, &s);
			}
			else
				cc->CreateUser(&profile, false);
		}
		else
		{
			auto mc = cc->GetContact(&pk);
			if(mc == 0)
			{
				resp->SendError(115);
				return true;
			}

			cc->RemoveContact(mc);
		}

		resp->SendVoid();
		return true;
	}

	return false;
}

bool MessageRelayCore::_ApiInvokeMsg(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp)
{
	if(action == rt::SS("receive_push"))
	{
		if(!resp->IsAsync())
		{
			resp->SendError(5);
			return true;
		}

		ApiMessagePushSelect select;
		rt::JsonObject arg(arguments);
		rt::String_Ref app = arg.GetValue("app").TrimSpace();
		rt::String_Ref conversation = arg.GetValue("recipient");

		if(!app.IsEmpty())
		{
			if(app.ToNumber(select.App) != app.GetLength())
			{
				resp->SendError(116, "app");
				return true;
			}

			select.Flag |= ApiMessagePushSelect::MPS_APP;
		}

		if(!conversation.IsEmpty())
		{
			if(!select.Conversation.FromString(conversation))
			{
				resp->SendError(114, conversation);
				return true;
			}

			select.Flag |= ApiMessagePushSelect::MPS_CONVERSATION;
		}

		{
			THREADSAFEMUTABLE_UPDATE(_ApiMessageTopics, topic);
			for(auto& t : topic.GetUnmodified())
			{
				if(t == select)
				{
					os::AtomicIncrement(rt::_CastToNonconst(&t.SubscriberCount));
					resp->SubscribePushTopic(t.PushTopicIndex);
					goto RECEIVE_PUSH_END;
				}
			}

			select.PushTopicIndex = resp->CreateNewPushTopic();
			select.SubscriberCount = 1;
			resp->SubscribePushTopic(select.PushTopicIndex);

			auto& list = topic.Get();
			for(auto& t : list)
			{
				if(t.SubscriberCount == 0)
				{
					t = select;
					goto RECEIVE_PUSH_END;
				}
			}

			list.push_back(select);
		}

RECEIVE_PUSH_END:
		resp->SendVoid();
		return true;
	}
	else if(action == rt::SS("get_pooled"))
	{
		rt::JsonObject arg(arguments);
		bool bundled = arg.GetValueAs("bundled", false);
		int64_t from = arg.GetValueAs<int64_t>("from", 0);
		int64_t to = arg.GetValueAs<int64_t>("to", 0x7fffffffffffffff);
		MrcAppId app = (MrcAppId)arg.GetValueAs("app", 0);
		uint16_t action = arg.GetValueAs("action", 0);
		uint16_t limit = arg.GetValueAs("limit", 16);
		DhtAddress swarm_addr;
		DhtAddress* p_swarm_addr = nullptr;

		if (swarm_addr.FromString(arg.GetValue("swarm")))
			p_swarm_addr = &swarm_addr;

		if (bundled)
		{
			GetPooled(p_swarm_addr, from, to, app, action, limit, resp->SendJsonReturnBegin().Array().GetInternalString());
			resp->SendJsonReturnEnd();
		}
		else
		{
			GetPooled(p_swarm_addr, from, to, app, action, limit, resp);
		}
		
		return true;
	}
	else if(action == rt::SS("get_media_state") || action == rt::SS("track_media_state"))
	{
		if(!_pMediaRelay)
		{
			resp->SendError(120);
			return true;
		}

		GdpHash hash;
		if(!hash.FromBase64(arguments.TrimQuotes()))
		{
			resp->SendError(114, arguments.TrimQuotes());
			return true;
		}

		MrcMediaOffloadItem item;
		if(!_pMediaRelay->LoadMediaOffloaded(hash, item))
		{
			resp->SendError(121, arguments.TrimQuotes());
			return true;
		}

		if(item.SecretHash.IsZero())
		{
			resp->SendError(122, arguments.TrimQuotes());
			return true;
		}
	
		int avail = _pMediaRelay->GetAvailability(hash);
		if(action[0] == 't' && avail > 0 && avail < 1000)
		{
			if(resp->IsAsync())
			{
				auto content = item.ContentType;
				auto size = item.OriginalSize();
				resp->YieldPolling([size,hash,content,this](LocalApiResponder* resp){
					int avail = _pMediaRelay->GetAvailability(hash);
					bool cont = avail > 0 && avail < 1000;
					resp->SendJsonReturnBegin().
						Object((
							J(hash) = tos_base64(hash),
							J(content_type) = content,
							J(size) = size,
							J(availability) = avail
						));
					resp->SendJsonReturnEnd(cont?LARE_CONTINUE:LARE_FINAL);
					return cont;
				});
			}
			else
			{
				resp->SendError(5);
			}

			return true;
		}
		else
		{
			resp->SendJsonReturnBegin().
				Object((
					J(hash) = tos_base64(hash),
					J(content_type) = item.ContentType,
					J(size) = item.OriginalSize(),
					J(availability) = avail
				));
			resp->SendJsonReturnEnd();
		}
	}
	else if(action == rt::SS("msg.get_media") || action == rt::SS("msg.get_media_raw"))
	{
		if(!_pMediaRelay)
		{
			resp->SendError(120);
			return true;
		}

		if(action.Last() == 'w' && resp->IsAsync())
		{
			resp->SendError(6);
			return true;
		}

		uint32_t priority = MMP_UI_AWAITING;
		uint32_t await = 0;
		GdpHash hash;
		
		if(arguments.TrimLeftSpace()[0] == '{')
		{
			rt::JsonObject arg(arguments);
			if(!hash.FromString(arg.GetValue("hash")))
			{
				resp->SendError(109, "hash");
				return true;
			}

			await = arg.GetValueAs<uint32_t>("await", 0);
			priority = arg.GetValueAs<uint32_t>("priority", MMP_UI_AWAITING);
		}
		else
		{
			if(!hash.FromBase64(arguments.TrimQuotes()))
			{
				resp->SendError(114, arguments.TrimQuotes());
				return true;
			}
		}

		if(await)
		{
			GdpAsyncDataFetch adf;
			resp->YieldGdpDataLoading(await, action.Last() == 'w', &adf);
			_pMediaRelay->Load(hash, &adf, priority);
			return true;
		}
		else
		{
			rt::BufferEx<uint8_t> data;
			if(_pMediaRelay->Load(hash, data))
			{
				if(action.Last() == 'w')
				{
					ASSERT(!resp->IsAsync());
					resp->SendRawResponse(data, data.GetSize());
				}
				else
				{
					resp->SendJsonReturnBegin().Binary(data, data.GetSize());
					resp->SendJsonReturnEnd();
				}
			}
			else
			{
				resp->SendError(121, tos_base64(hash));
			}
		}

		return true;
	}
	else if(action == rt::SS("text"))
	{
		DhtAddress swarm;
		bool is_default_swarm;
		MrcMessageAssembler assem(*this);
		if(!_ApiPrepareMessageSend(assem, arguments, swarm, is_default_swarm, resp))
			return true;

		rt::JsonObject arg(arguments);
		rt::String_Ref raw_content = arg.GetValue("content");
		rt::String content;
		rt::JsonObject::UnescapeStringValue(raw_content, content);
		
		if(content.IsEmpty())
		{
			resp->SendError(109, "content");
			return true;
		}

		if(content.GetLength() < 2048)
		{
			assem.SetContent(arg.GetValueAs<int>("content_type", MRC_CONTENT_TYPE_UTF8), content.Begin(), content.GetLength());
		}
		else
		{
			// sent as media attachment
		}

		assem.Finalize(assem.IsSealGreeting()? MPO_GREETING_REQUIRED : MPO_NONE);
		auto id = BroadcastEnvelope(*assem.GetSealed(), MRC_CONTACTPOINT_DURATION_MAX, true, is_default_swarm?nullptr:&swarm);

		if(id)
		{
			auto& ret = resp->SendJsonReturnBegin();
			ret.Object((
				J(swarm) = tos_base16(swarm),
				J(id) = rt::tos::Number(id),
				J(timestamp) = (int64_t)assem.GetSealed()->Time
			));
			resp->SendJsonReturnEnd();
		}
		else
		{
			resp->SendError(118, tos_base16(swarm));
		}

		return true;
	}

	return false;
}

bool MessageRelayCore::_ApiPrepareMessageSend(MrcMessageAssembler& assem, const rt::String_Ref& arguments, DhtAddress& swarm, bool& is_default_swarm, LocalApiResponder* resp) const
{
	auto* cc = _ContactsControl._pContacts;
	if(!cc || !cc->GetMyself())
	{
		resp->SendError(117);
		return false;
	}

	rt::JsonObject arg(arguments);
	rt::String_Ref val;
	MrcContact recipient;
	int app, action;

	{	val = arg.GetValue("recipient");
		PublicKey pk;
		if(!pk.FromString(val))
		{
			resp->SendError(114, val);
			return false;
		}

		recipient = cc->GetContact(&pk);
		if(!recipient)
		{
			resp->SendError(113, val);
			return false;
		}
	}

	app = arg.GetValueAs<int>("app");
	if(app <= 0 || app > 0xffff)
	{
		resp->SendError(116, "app");
		return false;
	}

	action = arg.GetValueAs<int>("action");
	if(action <= 0 || action > 0xffff)
	{
		resp->SendError(116, "action");
		return false;
	}

	rt::String_Ref swarm_str = arg.GetValue("swarm");
	is_default_swarm = swarm_str.IsEmpty();
	if(is_default_swarm)
	{
		auto default_sid = _pNetCore->SMB().GetDefaultSwarmId();
		if(default_sid)
		{
			swarm = *VERIFY(_pNetCore->SMB().GetAddressFromSwarmId(default_sid));
		}
		else
		{
			resp->SendError(119);
			return false;
		}
	}
	else
	{
		if(!swarm.FromString(swarm_str))
		{
			resp->SendError(107, swarm_str);
			return false;
		}

		auto sid = _pNetCore->SMB().GetSwarmIdFromAddress(swarm);
		if(!sid)
		{
			resp->SendError(118, swarm_str);
			return false;
		}
	}

	if(!assem.Create(recipient, app, action, _pNetCore->GetNetworkTime()))
	{
		resp->SendError(7);
		return false;
	}

	return true;
}

} // namespace upw