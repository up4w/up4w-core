#include "local_api.h"
#include "../netsvc_core.h"
#include "../gdp/gdp_base.h"


namespace upw
{

LocalApi::LocalApi(NetworkServiceCore* c)
	: _pCore(c)
	, _CommandHandler(c)
{
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	_JsonRpcPort = 0;
#endif
}

void LocalApi::Term()
{
	CoreEvents::Get().Unsubscribe(this);
	_EnableConsole(false);

	{	EnterWriteBlock(_ApiHandlerMapLock);
		_ApiHandlerMap.clear();
	}

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	_JsonRpcPort = 0;
	_JsonRpcSvc.Stop();
	_WebSocketSvc.Destory();
#endif
}

uint32_t LocalApi::AllocatePushTopic()
{
#if defined(OXD_SERVICE_DISABLE_HTTPD)
	return (uint32_t)os::AtomicIncrement((volatile int*)&_PushTopicIndexNext);
#else
	return _WebSocketSvc.AllocatePushTopic();
#endif
}

bool LocalApi::Init(int protocols, const rt::String_Ref& webapi_bind)
{
	bool any_proto_ok = false;
#if defined(OXD_SERVICE_DISABLE_HTTPD)
	_PushTopicIndexNext = 0;
#endif

	if(protocols&PROTO_CONSOLE)
		if(_EnableConsole(true))
			any_proto_ok = true;
		else
			_LOG_WARNING("[API]: failed to initialize console input");

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	if(protocols&(PROTO_HTTP|PROTO_WEBSOCKET))
	{
		ASSERT(!_JsonRpcSvc.IsRunning());
		_JsonRpcPort = 0;

		inet::InetAddr bind;
		if(webapi_bind.IsEmpty())
		{
			bind.SetAsLoopback();
		}
		else if(webapi_bind.HasOnlyNumbers())
		{
			bind.SetAsLoopback();
			bind.SetPort(webapi_bind.ToNumber<WORD>());
		}
		else
		{
			bind.SetAddress(ALLOCA_C_STRING(webapi_bind), 11800);
		}

		static const char* cmd_ep = "/cmd";
		static const char* api_ep = "/api";

		HttpEndpoint* endp[2] = { &_CommandHandler };
		_CommandHandler.SetEndPoint(cmd_ep);

		if(protocols&PROTO_WEBSOCKET)
		{
			_WebSocketSvc.SetEndPoint(api_ep);
			endp[1] = &_WebSocketSvc;

			_WebSocketSvc.Create(this);
			_WebSocketSvc.SetOnDataCallback(this, &LocalApi::_AsyncOnConnecting, &LocalApi::_AsyncOnDisconnected, &LocalApi::_AsyncOnMessage);
		}
		else
		{
			endp[1] = this;
		}

		SetEndPoint(api_ep);
		_JsonRpcSvc.SetEndpoints(endp, 2);

		if(_JsonRpcSvc.Start(bind, 0, NET_LOCAL_API_PENDCONN_COUNT))
		{	
			_JsonRpcPort = _JsonRpcSvc.GetBindedPort();

			bind = _JsonRpcSvc.GetBindedAddress();
			if(bind.IsAny())
				inet::GetLocalAddresses(&bind, 1, true);

			bind.SetPort(_JsonRpcPort);
			_LOG_HIGHLIGHT("[NET]: Command API is listening at http://"<<bind<<cmd_ep);
			if(protocols&PROTO_WEBSOCKET)
				_LOG_HIGHLIGHT("[NET]: JSON-PRC API is listening at ws://"<<bind<<api_ep);

			any_proto_ok = true;
		}
		else
		{
			_JsonRpcSvc.Stop();
			_LOG_WARNING("[API]: failed to initialize JSON-PRC/WebSocket");
		}
	}

	if(!any_proto_ok)
	{
		Term();
		return false;
	}
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)

	if(protocols&PROTO_NAMED_PIPE)
	{
		ASSERT(0);  // TBD
	}

	_CoreEventPushTopic = AllocatePushTopic();
	CoreEvents::Get().Subscribe(this);

	return true;
}

void LocalApi::OnTick(UINT tick)
{
	if(tick - _ConsoleRepeatCommandLastTick >= _ConsoleRepeatCommandInterval && !_ConsoleRepeatCommand.IsEmpty())
	{
		os::CommandLine cmd;
		{	EnterCSBlock(_ConsoleRepeatCommandCS);
			cmd.Parse(_ConsoleRepeatCommand);
		}
		_CommandHandler.ExecuteInConsole(cmd);
		_ConsoleRepeatCommandLastTick = tick;
	}

	if(tick%10 == 5)
	{
		for(int i=0;;)
		{
			YieldRequest r;

			{	EnterCSBlock(_YieldRequestsRollingCS);
				if(i >= _YieldRequestsRolling.GetSize())break;
				r = _YieldRequestsRolling[i];
			}

			if(!r.Invoke(this))
			{
				EnterCSBlock(_YieldRequestsRollingCS);
				if(_YieldRequestsRolling[i].ResponderStub == r.ResponderStub)
				{	_YieldRequestsRolling.erase(i);
					continue;
				}
				else
				{
					auto f = _YieldRequestsRolling.Find(r);
					if(f >= 0)
					{
						_YieldRequestsRolling.erase(f);
						if(f>i)i++;
						continue;
					}
				}
			}

			i++;
		}
	}
}

bool LocalApi::YieldRequest::Invoke(LocalApi* api)
{
	LocalApiResponder resp(api, ResponderStub);
	return Function(&resp) && resp.IsAlive();
}

bool LocalApi::_EnableConsole(bool yes, UINT cmdline_sizemax)
{
	if(yes)
	{
		if(!_ConsoleInput.IsRunning())
		{
			struct _on
			{
				static void input(LPSTR str, UINT len, LPVOID cookie)
				{
					ASSERT(str[len] == 0);  // zero-terminated

					auto* api = (LocalApi*)cookie;
					os::CommandLine cmd;
					cmd.Parse(str);

					if(cmd.GetTextCount())
					{
						if(api->_CommandHandler.ExecuteInConsole(cmd))
						{
							int repeat = -1;
							if(cmd.HasOption("repeat"))repeat = cmd.GetOptionAs<int>("repeat", 1);
							if(cmd.HasOption("r"))repeat = cmd.GetOptionAs<int>("r", 5);

							if(repeat > 0)
							{
								EnterCSBlock(api->_ConsoleRepeatCommandCS);
								api->_ConsoleRepeatCommand = rt::String_Ref(str, len);
								api->_ConsoleRepeatCommandInterval = repeat*10;
								api->_ConsoleRepeatCommandLastTick = api->_pCore->GetTick();
							}
						}
					}
					else
					{	
						_LOGC_PROMPT();
						// stop command repeating
						if(!api->_ConsoleRepeatCommand.IsEmpty())
						{
							EnterCSBlock(api->_ConsoleRepeatCommandCS);
							api->_ConsoleRepeatCommand.Empty();
							api->_ConsoleRepeatCommandInterval = 0;
						}
					}

				}
			};

			_ConsoleInput.Init(&_on::input, this, cmdline_sizemax);
		}
	}
	else
	{
		_ConsoleInput.Term();
	}

	return true;
}
#if !defined(OXD_SERVICE_DISABLE_HTTPD)

bool LocalApi::_AsyncOnConnecting(inet::WebSocketSvc::Connection* c)
{
	//_WebSocketSvc.SubscribePushTopic(_CoreEventPushTopic, c);
	return true;
}

void LocalApi::_AsyncOnDisconnected(inet::WebSocketSvc::Connection* c)
{
}

void LocalApi::_AsyncOnMessage(inet::WebSocketSvc::Connection* c, LPSTR msg, int32_t len)
{
	rt::String_Ref req, inc, arg;
	{
		rt::JsonObject obj(msg, len);
		rt::JsonKeyValuePair jk;
		while(obj.GetNextKeyValuePair(jk))
		{
			if(jk.GetKey() == "req"){ req = jk.GetValue(); continue; }
			if(jk.GetKey() == "inc"){ inc = jk.GetValue(); continue; }
			if(jk.GetKey() == "arg"){ arg = jk.GetValue(); continue; }
		}
	}

    LocalApiResponder responder(this, c, req, inc);
	_OnApiInvoke(responder, arg);
}

bool LocalApi::OnRequest(inet::HttpResponse& resp)
{
	rt::String_Ref req = resp.GetQueryParam("req");
	rt::String_Ref inc = resp.GetQueryParam("inc");
	rt::String_Ref arg = resp.GetQueryParam("arg");
	if(!arg.IsEmpty())
	{
		arg = rt::String_Ref(arg.Begin(), resp.Query.End());
	}
	else
	{
		arg = resp.Body;
	}

	LocalApiResponder ret(this, &resp, resp.GetQueryParam("req"), resp.GetQueryParam("inc"));

	if(!arg.IsEmpty())
	{
		if(req.Begin() > arg.Begin())
		{
			ret.SendError(4);
			return true;
		}

		if(inc.Begin() > arg.Begin())inc.Empty();
	}
	
    LocalApiResponder responder(this, &resp, resp.GetQueryParam("req"), resp.GetQueryParam("inc"));
	_OnApiInvoke(responder, arg);
	return true;
}

#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)

void LocalApi::_YieldRequestRolling(LocalApiResponder* resp, const YieldRequestFunc& func)
{
	rt::String req = resp->GetRequest();
	rt::String inc = resp->GetNonce();

	{	EnterCSBlock(_YieldRequestsRollingCS);
		auto& y = _YieldRequestsRolling.push_back();

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
		if(resp->_pWebSocketConn){ y.ResponderStub.WebSocketConn = resp->_pWebSocketConn; resp->_pWebSocketConn->AddIORef(); }
		if(resp->_pHttpConn){ y.ResponderStub.HttpConn = resp->_pHttpConn->TakeOver(); }
#endif

		rt::Swap(y.ResponderStub.InvocationNonce, inc);
		rt::Swap(y.ResponderStub.RequestAction, req);
		y.Function = func;
	}
}

void LocalApi::_OnApiInvoke(LocalApiResponder& resp, const rt::String_Ref& arg)
{
	static const rt::CharacterSet sep(".:/");
	rt::String_Ref req_seg[2];
	if(resp._RequestAction.Split(req_seg, 2, sep) != 2)
	{
		resp.SendError(1);
		return;
	}

	AsyncApiHandler* handler;
	{	EnterReadBlock(_ApiHandlerMapLock);
		handler = _ApiHandlerMap.get(req_seg[0]);
		if(!handler)
		{
			resp.SendError(2, resp._RequestAction);
			return;
		}
	}

	if(!handler->OnApiInvoke(req_seg[1], arg, &resp))
		resp.SendError(3, resp._RequestAction);
}

void LocalApi::OnCoreEventNotify(DWORD module_id, DWORD msg_id, LPCSTR json, UINT json_size)
{
	// TBD: send by Pipe
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	auto& composer = LocalApiResponder::_ThreadLocalComposer();
	composer.Compose("core.event");
	composer.ScopeReturnBegin().
		Object((
			J(mod) = module_id,
			J(evt) = msg_id,
			J_IF(json_size&&json, (J(msg) = rt::_JVal(rt::String_Ref(json, json_size))))
		));
	composer.ScopeReturnEnd();

	PushJsonResponse(_CoreEventPushTopic, composer.GetJsonString());
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)
}

void LocalApi::PushJsonResponse(uint32_t topic_index, const rt::String_Ref& msg)
{
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	if(_WebSocketSvc.IsCreated())
		_WebSocketSvc.Push(msg.Begin(), (uint32_t)msg.GetLength(), topic_index);
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)
}

void LocalApi::SetApiHandler(const rt::String_Ref& module_name, AsyncApiHandler* h)
{
	EnterWriteBlock(_ApiHandlerMapLock);
	ASSERT(_ApiHandlerMap.get(module_name) == nullptr);
	_ApiHandlerMap.insert(module_name, h);
}

void LocalApi::RemoveApiHandler(const rt::String_Ref& module_name)
{
	EnterWriteBlock(_ApiHandlerMapLock);
	_ApiHandlerMap.erase(module_name);
}

} // namespace oxd