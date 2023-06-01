#pragma once
#include "../netsvc_core.h"

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
#include "../../externs/miniposix/core/inet/tinyhttpd.h"
#include "../../externs/miniposix/core/inet/tinyhttpd_websocket.h"
#include "../../externs/miniposix/core/inet/tinyhttpd_fileserv.h"
#endif

namespace upw
{

struct GdpAsyncDataFetch;

class CommandHandler  // synchonized command via console and HTTP only
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	: public inet::HttpHandler<CommandHandler>
#endif
{
protected:
	NetworkServiceCore*	_pCore;
	bool				_ExecuteBuiltIn(const os::CommandLine& cmd, rt::String& out);
	void				_ExecuteScript(rt::String& script, const rt::String_Ref& fn);
	bool				_ExecuteInScriptCommands(const os::CommandLine& cmd);
	void				_DoExit();

protected:
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	bool				OnRequest(inet::HttpResponse& resp);
#endif

	//Command
	THISCALL_POLYMORPHISM_DECLARE(bool, false, OnCommandExecute, const os::CommandLine& cmd, rt::String& out);
	struct OnExecuteCallbackItem
	{	
		LPVOID			Obj;
		THISCALL_MFPTR	OnExecute;
		OnExecuteCallbackItem(){ Obj = nullptr; OnExecute.Zero(); }
	};
	rt::hash_map<rt::String, OnExecuteCallbackItem, rt::String::hash_compare>	_ExtendedCommandExecution;
	os::CriticalSection	_ExtendedCommandExecutionCS;

public:
	CommandHandler(NetworkServiceCore* c):_pCore(c){}
	~CommandHandler();
	bool		Execute(const os::CommandLine& cmd, rt::String& out);
	bool		ExecuteInConsole(const os::CommandLine& cmd);
	void		SetExtension(const rt::String_Ref& prefix, LPVOID obj, const THISCALL_MFPTR& exec = nullptr);
	void		RemoveExtension(const rt::String_Ref& prefix);
	static bool	IsStringJson(const rt::String_Ref& s);
};

class LocalApi;
class LocalApiResponder;

struct LocalApiResponderStub
{
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	inet::WebSocketSvc::Connection*		WebSocketConn = nullptr;
// patch for "externs\miniupnpc\miniupnpc_socketdef.h" {
#undef SOCKET
// } patch
	inet::SOCKET						HttpConn = INVALID_SOCKET;
#endif

	rt::String		InvocationNonce;
	rt::String		RequestAction;

	bool			operator == (const LocalApiResponderStub& x) const { return x.InvocationNonce == InvocationNonce && x.RequestAction == RequestAction; }
};

enum LocalApiResponderEnding
{
	LARE_NONE,
	LARE_CONTINUE,
	LARE_FINAL,
};

class LocalApiResponder
{
	friend class LocalApi;
	friend class MessageRelayCore;
public:
	class Message
	{	// <Perfix><Json>
		rt::Json	_Json;
		rt::ObjectPlaceHolder<rt::Json::_AppendingKeyedValue>	_ScopeReturn;

	public:
		void	Compose(const rt::String_Ref& req, const rt::String_Ref& inc = nullptr);
		void	ComposeError(const rt::String_Ref& req, const rt::String_Ref& inc, int err_code, const rt::String_Ref& err_msg, const rt::String_Ref& err_msg_add = nullptr);
		void	SetSeries(bool continue_or_final); // true = continue
		auto	GetJsonString() const { ASSERT(!_ScopeReturn.IsInitialized()); return _Json.GetInternalString(); }
	
		auto&	ScopeReturnBegin(){ _ScopeReturn.Init(_Json.ScopeAppendingKey("ret")); return _Json; }
		void	ScopeReturnEnd(){ _ScopeReturn.Term(); }
	};

protected:
	LocalApi*							_pAPI;
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	inet::WebSocketSvc::Connection*		_pWebSocketConn = nullptr;
	inet::HttpResponse*					_pHttpConn = nullptr;
	rt::ObjectPlaceHolder<inet::HttpResponse>	_HttpConnFromStub;
#endif

	bool								_bAlive = true;
	bool								_Responded = false;
	rt::String_Ref						_RequestAction;
	rt::String_Ref						_InvocationNonce;
	static auto&						_ThreadLocalComposer(){ thread_local Message _; return _; }

	struct YieldLoad
	{
		LocalApi*						API = nullptr;
		LocalApiResponderStub			ResponderStub;
		bool							AsRaw = false;
	};

public:
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	LocalApiResponder(LocalApi* api, inet::WebSocketSvc::Connection* ws, const rt::String_Ref& req, const rt::String_Ref& inc);
	LocalApiResponder(LocalApi* api, inet::HttpResponse* http, const rt::String_Ref& req, const rt::String_Ref& inc);
	bool		IsAsync() const { return !_pHttpConn; }
#else
	bool		IsAsync() const { return true; }
#endif
	LocalApiResponder(LocalApi* api, const LocalApiResponderStub& stub);
	~LocalApiResponder();

	bool		IsAlive() const { return _bAlive; }
	bool		IsResponded() const { return _Responded; }
	auto		GetRequest() const { return _RequestAction; }
	auto		GetNonce() const { return _InvocationNonce; }

	void		SendRawResponse(const void* data, uint32_t size);
	void		SendResponse(const rt::String_Ref& data, uint32_t tinyhttpd_mime);
	void		SendError(int err_code, const rt::String_Ref& err_msg = nullptr);
	void		SendVoid();
	rt::Json&	SendJsonReturnBegin();
	void		SendJsonReturnEnd(LocalApiResponderEnding ending_condition = LARE_NONE); // 0:not specified, 1:continue, 2:finalized

	void		SubscribePushTopic(uint32_t topic_index);
	uint32_t	CreateNewPushTopic();

	static auto	GetErrorMessage(uint32_t err_code) -> rt::String_Ref;
	void		YieldPolling(const std::function<bool(LocalApiResponder* resp)>& action);
	void		YieldGdpDataLoading(uint32_t timeout, bool as_raw, GdpAsyncDataFetch* out) const;
};



} // namespace upw
