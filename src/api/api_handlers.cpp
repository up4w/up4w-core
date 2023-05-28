#include "api_handlers.h"
#include "local_api.h"
#include "../netsvc_core.h"
#include "../dht/dht.h"
#include "../gdp/gdp_base.h"

#if defined(OXD_SERVICE_DISABLE_HTTPD)
#include "../../externs/miniposix/core/inet/tinyhttpd.h"
#endif

namespace upw
{

bool CommandHandler::_ExecuteBuiltIn(const os::CommandLine& cmd, rt::String& out)
{
	rt::String_Ref name(cmd.GetText(0));
	if(name == "quit" || name == "exit" || name == "shutdown")
	{
		_DoExit();
		return true;
	}
	
	if(name == "log")
	{
		bool d;
		if(rt::String_Ref(cmd.GetText(1)) == "on")
		{	d = true;
		}
		else if(rt::String_Ref(cmd.GetText(1)) == "off")
		{	d = false;
		}
		else
			d = !os::LogIsDisplayInConsole();
				
		os::LogDisplayInConsole(d);
		out = ( J(showlog) = d );
		return true;
	}

#if defined(PLATFORM_WIN) || defined(PLATFORM_MAC) || defined(PLATFORM_LINUX)
	if(name == "cd")
	{
		rt::String arg = cmd.GetText(1);
		if(arg.IsEmpty())
			os::File::GetCurrentDirectory(out);
		else
		{
			os::File::ResolveRelativePath(arg, out);
			if(!os::File::SetCurrentDirectory(out))
				out = "ERR: No such directory";
		}

		return true;
	}

	if(name == "dir" || name == "ls")
	{
		os::FileList list;

		LPCSTR dir = cmd.GetText(1);
		if(!dir)dir = "./";

		DWORD flag = 0;
		if(!cmd.HasOption("h"))flag |= os::FileList::FLAG_SKIPHIDDEN;
		if(cmd.HasOption("s"))flag |= os::FileList::FLAG_RECURSIVE;

		UINT co = list.Populate(dir, nullptr, flag);

		out += rt::SS("Total ") + co + " files and directories are found in \"" + dir + '"';
		if(flag&os::FileList::FLAG_RECURSIVE)out += rt::SS(" and all subdirectories");
		if(!(flag&os::FileList::FLAG_SKIPHIDDEN))out += rt::SS(" including hidden ones");

		for(UINT i=0; i<co; i++)
		{
			auto& fn = list.GetFullpath(i);
			ULONGLONG sz = os::File::GetFileSize(fn);
			if(sz == 0 && os::File::IsDirectory(fn))
			{	_LOGC("    <DIR> "<<list.GetFilename(i).TrimLeft(1));
			}
			else
			{	_LOGC((rt::tos::FileSize<true,true>(sz).RightAlign(9))<<' '<<list.GetFilename(i).TrimLeft(1));
			}
		}

		return true;
	}

	if(name == "run" || name == "call")
	{
		LPCSTR fn = cmd.GetText(1);
		if(fn && fn[0])
		{
			rt::String script;
			if(	(	os::File::LoadText(fn, script) || 
					os::File::LoadText(rt::String_Ref(fn) + ".nbs", script)
				)
				&& !script.IsEmpty()
			)
			{
				_ExecuteScript(script, fn);
				script.SecureEmpty();
				out = '\n';
			}
			else
				out = rt::SS("ERR: Script file '") + fn + "' is not exist or is empty";
		}
		else
		{
			out = rt::SS("ERR: Script file not specified");
		}

		return true;
	}
#endif // #if defined(PLATFORM_WIN) || defined(PLATFORM_MAC) || defined(PLATFORM_LINUX)

	return false;
}

void CommandHandler::_ExecuteScript(rt::String& script, const rt::String_Ref& fn)
{
	static const rt::SS _code_scope("```");
	os::CommandLine cmdline;

	rt::String_Ref line;
	while(script.GetNextLine(line, true))
	{
		if(line == _code_scope)
		{	// skip isolated code block
			do
			{	script.GetNextLine(line, false);
			}while(line != "```");
			continue;
		}
		else if(line.StartsWith("###")) // comment
		{	continue;
		}
		else if(line.StartsWith("##"))	// echo
		{
			_LOGC(line.SubStr(2).TrimSpace());
			continue;
		}
		else if(line.StartsWith("#"))	// echo highlighted
		{
			_LOG_HIGHLIGHT(line.SubStr(1).TrimSpace());
			continue;
		}

		rt::String_Ref cmd = line;
		while(line.Last() == '\\')
			script.GetNextLine(line, true);

		rt::String append;
		if(line == rt::SS("```"))
		{
			cmd = rt::String_Ref(cmd.Begin(), line.Begin()).TrimSpace();
			append = line;
			do
			{	script.GetNextLine(line, false);
			}while(line != "```");
			append = rt::String_Ref(append.Begin() + 3, line.Begin()).TrimSpace();
		}
		else
			cmd = rt::String_Ref(cmd.Begin(), line.End());
		
		_LOGC(cmd);
		cmdline.Parse(ALLOCA_C_STRING(cmd));

		if(rt::SS("exit") == cmdline.GetText(0) || rt::SS("quit") == cmdline.GetText(0)) // stop script
			return;

		if(!append.IsEmpty())cmdline.AppendText(append);
		if(_ExecuteInScriptCommands(cmdline))continue;

		ExecuteInConsole(cmdline);
	}
}

bool CommandHandler::_ExecuteInScriptCommands(const os::CommandLine& cmd)
{
	rt::String_Ref name(cmd.GetText(0));
	if(name == rt::SS("wait"))
	{
		rt::String_Ref arg(cmd.GetText(1));
		if(arg.IsEmpty())
		{
			_LOGC("Wait a second ...");
			os::Sleep(1000, &_pCore->bWantStop);
			return true;
		}

		UINT t;
		if(arg.ToNumber(t) == arg.GetLength())
		{
			_LOGC("Wait "<<rt::tos::TimeSpan<>(t)<<" ...");
			os::Sleep(t, &_pCore->bWantStop);
			return true;
		}
	}

	return false;
}

bool CommandHandler::Execute(const os::CommandLine& cmd, rt::String& out)
{
	if(_ExecuteBuiltIn(cmd, out))return true;

	rt::String_Ref name(cmd.GetText(0));

	OnExecuteCallbackItem item;
	{
		EnterCSBlock(_ExtendedCommandExecutionCS);
		rt::String_Ref prefix = name.TrimAfter('.');

		auto it = _ExtendedCommandExecution.find(prefix);
		if(it == _ExtendedCommandExecution.end())
			return false;

		item = it->second;
	}

	return THISCALL_POLYMORPHISM_INVOKE(OnCommandExecute, item.Obj, item.OnExecute, cmd, out);
}

void CommandHandler::_DoExit()
{
	os::SetLogConsolePrompt(nullptr);
	_pCore->bWantStop = true;
	CoreEvent(MODULE_CORE, CORE_EXIT);
}

CommandHandler::~CommandHandler()
{
	os::SetLogConsolePrompt(nullptr);
}

bool CommandHandler::IsStringJson(const rt::String_Ref& s)
{
	rt::String_Ref t = s.TrimSpace();
	return (t[0] == '{' && t.Last() == '}') || (t[0] == '[' && t.Last() == ']');
}

bool CommandHandler::ExecuteInConsole(const os::CommandLine& cmd)
{
	thread_local rt::String out;
	thread_local rt::JsonBeautified json;

	out.Empty();

	bool ret = Execute(cmd, out);

	bool display = true;
	if(!os::LogIsDisplayInConsole())
	{
		display = false;
		os::LogDisplayInConsole(true);
	}

	if(out.IsEmpty())
	{	
		if(ret)
		{	_LOGC("OK: Command executed.");
		}
		else
		{	_LOGC("ERR: Command execution failed, or is not recognized.");
		}
	}
	else
	{
		if(IsStringJson(out))
		{
			json.Beautify(out, 2);
			_LOGC(json);
		}
		else
			_LOGC(out);
	}

	os::LogDisplayInConsole(display);

	out.SecureEmpty();
	json.SecureEmpty();
	return ret;
}

void CommandHandler::SetExtension(const rt::String_Ref& prefix, LPVOID obj, const THISCALL_MFPTR& exec)
{
	EnterCSBlock(_ExtendedCommandExecutionCS);

	if(obj)
	{
		ASSERT(!exec.IsNull());

		auto& item = _ExtendedCommandExecution[prefix];
		item.Obj = obj;
		item.OnExecute = exec;
	}
	else
	{
		_ExtendedCommandExecution.erase(prefix);
	}
}

void CommandHandler::RemoveExtension(const rt::String_Ref& prefix)
{
	EnterCSBlock(_ExtendedCommandExecutionCS);
	_ExtendedCommandExecution.erase(prefix);
}

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
bool CommandHandler::OnRequest(inet::HttpResponse& resp)
{
	thread_local os::CommandLine cmd;
	thread_local rt::String	out;

	if(resp.Body.IsEmpty())
	{	
		cmd.ParseURI(resp.GetLnPath(this).TrimLeft(1), resp.Query);
		if(cmd.GetTextCount() == 0)
			return false;
	}
	else
	{
		ASSERT(resp.Body.IsZeroTerminated());
		cmd.Parse(resp.Body.Begin());
	}

	out.Empty();
	bool ret = Execute(cmd, out);
	if(out.IsEmpty())
	{
		resp.Send(ret?"true":"false", ret?4:5, inet::TinyHttpd::_MIMEs[inet::TinyHttpd::MIME_JS]);
	}
	else
	{
		resp.Send(out.Begin(), (int)out.GetLength(), inet::TinyHttpd::_MIMEs[CommandHandler::IsStringJson(out)?inet::TinyHttpd::MIME_JS:inet::TinyHttpd::MIME_TEXT]);
	}

	return true;
}
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
LocalApiResponder::LocalApiResponder(LocalApi* api, inet::WebSocketSvc::Connection* ws, const rt::String_Ref& req, const rt::String_Ref& inc)
	:_RequestAction(req)
	,_InvocationNonce(inc)
{
	_pAPI = api;
	_pWebSocketConn = ws;
}

LocalApiResponder::LocalApiResponder(LocalApi* api, inet::HttpResponse* http, const rt::String_Ref& req, const rt::String_Ref& inc)
	:_RequestAction(req)
	,_InvocationNonce(inc)
{
	_pAPI = api;
	_pHttpConn = http;
}
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)

LocalApiResponder::LocalApiResponder(LocalApi* api, const LocalApiResponderStub& stub)
	:_RequestAction(stub.RequestAction)
	,_InvocationNonce(stub.InvocationNonce)
{
	_pAPI = api;

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	_pWebSocketConn = stub.WebSocketConn;
	if(stub.HttpConn != INVALID_SOCKET)
	{
		_HttpConnFromStub.Init();
		_HttpConnFromStub->Attach(stub.HttpConn);
		_pHttpConn = _HttpConnFromStub;
	}
#endif
}

LocalApiResponder::~LocalApiResponder()
{
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	if(_HttpConnFromStub.IsInitialized())
		_HttpConnFromStub->TakeOver(); // prevent socket being closed
#endif
}

void LocalApiResponder::SendRawResponse(const void* data, uint32_t size)
{
	if(!_bAlive)return;

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	if(_pWebSocketConn){ ASSERT(0); }
	else if(_pHttpConn)
	{
		_pHttpConn->Send(data, size, inet::TinyHttpd::_MIMEs[inet::TinyHttpd::MIME_BINARY]);
		_bAlive = false;
	}
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)

	_Responded = true;
}

void LocalApiResponder::SendResponse(const rt::String_Ref& data, uint32_t tinyhttpd_mime)
{
	ASSERT(tinyhttpd_mime < sizeofArray(inet::TinyHttpd::_MIMEs));
	if(!_bAlive)return;

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	if(_pWebSocketConn)
	{
		switch(tinyhttpd_mime)
		{
		case inet::TinyHttpd::MIME_JSON:
			if(!_pWebSocketConn->SendData(data)) // json
				_bAlive = false;
			break;
		case inet::TinyHttpd::MIME_TEXT:
		case inet::TinyHttpd::MIME_XML:
		case inet::TinyHttpd::MIME_HTML:
			{	// as escaped text
				auto& msg = SendJsonReturnBegin();
				auto& str = msg.GetInternalString();
				str += '"';
				rt::JsonEscapeString::Concat(data, str);
				str += '"';
				SendJsonReturnEnd();
			}
			break;
		default:
			{	// as base64 encoded binary
				auto& msg = SendJsonReturnBegin();
				auto& str = msg.GetInternalString();
				str += '"';
				auto prev_size = str.GetLength();
				auto base64_size = os::Base64EncodeLength(data.GetLength());
				str.SetLength(prev_size + base64_size + 1);

				char* p = &str[prev_size];
				os::Base64Encode(p, data.Begin(), data.GetLength());
				str[prev_size + base64_size] = '"';

				SendJsonReturnEnd();
			}
			break;
		}
	}
	else if(_pHttpConn)
	{
		ASSERT(!_Responded);
		_pHttpConn->Send(data.Begin(), (int)data.GetLength(), inet::TinyHttpd::_MIMEs[tinyhttpd_mime]);
		_bAlive = false;
	}
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)

	_Responded = true;
}

void LocalApiResponder::SubscribePushTopic(uint32_t topic_index)
{
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	if(_pWebSocketConn)
		_pAPI->_WebSocketSvc.SubscribePushTopic(topic_index, _pWebSocketConn);
#endif // #if !defined(OXD_SERVICE_DISABLE_HTTPD)	

	// TBD subscribe for pipe
}

uint32_t LocalApiResponder::CreateNewPushTopic()
{
	return _pAPI->AllocatePushTopic();
}

void LocalApiResponder::SendError(int err_code, const rt::String_Ref& err_msg_addition)
{
	auto& msg = _ThreadLocalComposer();
	rt::String_Ref err_msg = GetErrorMessage(err_code);
	if(err_msg.IsEmpty())
	{
		err_msg = rt::SS("Unknown error, explaination not available");
		msg.ComposeError(_RequestAction, _InvocationNonce, err_code, err_msg);
	}
	else
	{
		msg.ComposeError(_RequestAction, _InvocationNonce, err_code, err_msg, err_msg_addition);
	}

	msg.ComposeError(_RequestAction, _InvocationNonce, err_code, err_msg, err_msg_addition);
	SendResponse(msg.GetJsonString(), inet::TinyHttpd::MIME_JSON);
}

void LocalApiResponder::SendVoid()
{
	SendJsonReturnBegin().Null();
	SendJsonReturnEnd();
}

rt::Json& LocalApiResponder::SendJsonReturnBegin()
{
	auto& msg = _ThreadLocalComposer();
	msg.Compose(_RequestAction, _InvocationNonce);
	return msg.ScopeReturnBegin();
}

void LocalApiResponder::SendJsonReturnEnd(LocalApiResponderEnding ending_condition)
{
	auto& msg = _ThreadLocalComposer();
	msg.ScopeReturnEnd();
	if(ending_condition)
		msg.SetSeries(ending_condition - 1);

	SendResponse(msg.GetJsonString(), inet::TinyHttpd::MIME_JSON);
}

void LocalApiResponder::Message::Compose(const rt::String_Ref& req, const rt::String_Ref& inc)
{
	_Json.Empty().Object((
		J(rsp) = req,
		J_IF(!inc.IsEmpty(), (J(inc) = inc))
	));
}

void LocalApiResponder::Message::ComposeError(const rt::String_Ref& req, const rt::String_Ref& inc, int err_code, const rt::String_Ref& err_msg, const rt::String_Ref& err_msg_add)
{
	_Json.Empty().Object((
		J(rsp) = req,
		J_IF(!inc.IsEmpty(), (J(inc) = inc)),
		J(err) = err_code
	));

	SSIZE_T pos;
	if((pos = err_msg.FindCharacter("$"))>=0 && !err_msg_add.IsEmpty())
	{
		auto u = _Json.ScopeWritingStringEscapedAtKey("ret");
		_Json.AppendStringEscaped(err_msg.SubStrHead(pos));
		_Json.AppendStringEscaped(err_msg_add);
		_Json.AppendStringEscaped(err_msg.SubStr(pos+1));
	}
	else
	{
		_Json.AppendKeyWithString("ret", err_msg);
	}
}

void LocalApiResponder::Message::SetSeries(bool continue_or_final)
{
	_Json.AppendKey("fin", !continue_or_final);
}

void LocalApiResponder::YieldPolling(const std::function<bool(LocalApiResponder* resp)>& action)
{
	ASSERT(IsAsync());
	_pAPI->_YieldRequestRolling(this, action);
}

void LocalApiResponder::YieldGdpDataLoading(uint32_t timeout, bool as_raw, GdpAsyncDataFetch* out) const
{
	struct _call
	{
		static void _func(void* cookie, const GdpData* data)
		{
			auto* y = (YieldLoad*)cookie;

			LocalApiResponder resp(y->API, y->ResponderStub);

			if(data && data->Data)
			{
				if(y->AsRaw)
				{
					resp.SendRawResponse(data->Data, data->Size);
				}
				else
				{
					resp.SendJsonReturnBegin().Binary(data->Data, data->Size);
					resp.SendJsonReturnEnd();
				}
			}
			else
			{
				resp.SendError(123);
			}

			_SafeDel(y);
		}
	};

	auto* req = _New(YieldLoad);
	req->API = _pAPI;
	req->AsRaw = as_raw;
	req->ResponderStub.InvocationNonce = _InvocationNonce;
	req->ResponderStub.RequestAction = _RequestAction;

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	if(_pWebSocketConn){ req->ResponderStub.WebSocketConn = _pWebSocketConn; _pWebSocketConn->AddIORef(); }
	if(_pHttpConn){ req->ResponderStub.HttpConn = _pHttpConn->TakeOver(); }
#endif

	out->Timeout = timeout;
	out->Callback = _call::_func;
	out->Cookie = req;
}

} // namespace upw