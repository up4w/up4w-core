#pragma once
#include "api_handlers.h"


namespace upw
{
class NetworkServiceCore;
struct GdpData;

class LocalApi: public CoreEventSink
#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	, protected inet::HttpHandler<LocalApi>
#endif
{
	friend class LocalApiResponder;
protected:
	bool				_bShared = false;
	NetworkServiceCore*	_pCore;

	//Console
	os::ConsolePrompt	_ConsoleInput;
	os::CriticalSection	_ConsoleRepeatCommandCS;
	rt::String			_ConsoleRepeatCommand;
	UINT				_ConsoleRepeatCommandInterval = 0;
	UINT				_ConsoleRepeatCommandLastTick;
	bool				_EnableConsole(bool yes = true, UINT cmdline_sizemax = 1024);

	//CommandLine API
	CommandHandler		_CommandHandler;
	virtual void		OnCoreEventNotify(DWORD module_id, DWORD msg_id, LPCSTR json, UINT json_size);

#if defined(OXD_SERVICE_DISABLE_HTTPD)
	volatile uint32_t	_PushTopicIndexNext = 0;
#else
	int					_JsonRpcPort;
	inet::TinyHttpd		_JsonRpcSvc;
	bool				OnRequest(inet::HttpResponse& resp);

	//WebSocket API
	inet::WebSocketSvc	_WebSocketSvc;
	bool				_AsyncOnConnecting(inet::WebSocketSvc::Connection* c);
	void				_AsyncOnDisconnected(inet::WebSocketSvc::Connection* c);
	void				_AsyncOnMessage(inet::WebSocketSvc::Connection* c, LPSTR msg, int32_t len);
#endif

	uint32_t			_CoreEventPushTopic;
	void				_OnApiInvoke(LocalApiResponder& resp, const rt::String_Ref& arg);

	os::ReadWriteMutex								_ApiHandlerMapLock;
	ext::fast_map_ptr<rt::String, AsyncApiHandler>	_ApiHandlerMap;

	typedef std::function<bool(LocalApiResponder* resp)>	YieldRequestFunc;
	struct YieldRequest
	{
		LocalApiResponderStub			ResponderStub;
		YieldRequestFunc				Function;
		bool							Invoke(LocalApi* api);
		bool operator == (const YieldRequest& x) const { return x.ResponderStub == ResponderStub; }
	};
	os::CriticalSection					_YieldRequestsRollingCS;
	rt::BufferEx<YieldRequest>			_YieldRequestsRolling;
	void								_YieldRequestRolling(LocalApiResponder* resp, const YieldRequestFunc& func);

public:
	enum {
		PROTO_HTTP		= 1<<0,
		PROTO_WEBSOCKET	= 1<<1,
		PROTO_NAMED_PIPE= 1<<2,
		PROTO_CONSOLE	= 1<<3,
	};

	LocalApi(NetworkServiceCore* c);
	~LocalApi(){ Term(); }

	bool		Init(int protocols = PROTO_HTTP|PROTO_CONSOLE, const rt::String_Ref& webapi_bind = nullptr);
	void		Term();
	bool		HasConsole() const { return _ConsoleInput.IsRunning(); }
	uint32_t	AllocatePushTopic();
	void		OnTick(UINT tick);

	// API Handler
	void		SetApiHandler(const rt::String_Ref& module_name, AsyncApiHandler*);
	void		RemoveApiHandler(const rt::String_Ref& module_name);
	void		PushJsonResponse(uint32_t topic_index, const rt::String_Ref& msg);

	// CommandLine API
	void		SetCommandExtension(const rt::String_Ref& prefix, LPVOID obj, const THISCALL_MFPTR& exec = nullptr){ _CommandHandler.SetExtension(prefix, obj, exec); }
	void		RemoveCommandExtension(const rt::String_Ref& prefix){ _CommandHandler.RemoveExtension(prefix); }
	bool		Execute(const os::CommandLine& cmd, rt::String& out){ return _CommandHandler.Execute(cmd, out); }

#if !defined(OXD_SERVICE_DISABLE_HTTPD)
	int			GetJsonRpcPort() const { return _JsonRpcPort; }
	rt::String	GetServerURL() const { return rt::SS("http://") + rt::tos::ip(_JsonRpcSvc.GetBindedAddress()) + L1_Path; }
#endif
};


} // namespace oxd