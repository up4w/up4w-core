#pragma once



#include "../rt/string_type_ops.h"
#include "../rt/buffer_type.h"
#include "../os/kernel.h"
#include "../os/multi_thread.h"
#include "../ext/concurrentqueue/async_queue.h"
#include "inet.h"
#include <map>
#include <mutex>
#include <condition_variable>
#include <list>

namespace inet
{
/** \defgroup tinyhttpd tinyhttpd
 * @ingroup inet
 *  @{
 */
class TinyHttpd;
class HttpResponse;
struct HttpEndpoint;

typedef HttpEndpoint* LPHTTPENDPOINT;
typedef const HttpEndpoint* LPCHTTPENDPOINT;

typedef void (*FUNC_HTTP_HANLDER_RELEASE)(LPHTTPENDPOINT pThis);
typedef bool (*FUNC_HTTP_HANLDER)(HttpResponse*, LPHTTPENDPOINT pThis);
typedef bool (*FUNC_WebAssetsConvertion)(const rt::String_Ref& fn, LPCVOID data, SIZE_T datasize, rt::BufferEx<BYTE>& out);

struct HttpEndpoint
{	
protected:
	rt::String				L1_Path;
	FUNC_HTTP_HANLDER		Handler;
public:
	const rt::String_Ref&	GetEndPoint() const { return L1_Path; }
	void					SetEndPoint(LPCSTR path){ L1_Path = path; }
	bool					HandleRequest(HttpResponse* resp){ return Handler(resp, this); }
};

enum _tagHttpVerb
{
	HTTP_GET = 0x20544547,  ///< 'GET '
	HTTP_POST = 0x54534f50	///< 'POST'
};

class HttpResponse
{
	friend class TinyHttpd;
	friend class WebSocket;
	bool				__FirstJsonObject;
protected:
	bool				_Send(LPCVOID p, int len);
	SocketTimed			_SocketAccepted;
	bool				_JSON_Only;
	rt::BufferEx<BYTE>	_Workspace;

public:
	struct sockaddr_in	_RemoteName;
	operator SOCKET(){	return _SocketAccepted;	}

	UINT				_RequestHeaderSize;

	DWORD				HttpVerb;
	rt::String_Ref		URI;
	rt::String_Ref		Query;
	rt::String_Ref		RemainHeader;
	rt::String_Ref		Body;
	rt::String_Ref		GetHeaderField(LPCSTR name) const;
	rt::String_Ref		GetQueryParam(const rt::String_Ref& name);
	template<typename T>
	T					GetQueryParam(const rt::String_Ref& name, T defval)
						{	rt::String_Ref s = GetQueryParam(name);
							if(!s.IsEmpty())s.ToNumber(defval);
							return defval;					
						}
	rt::String_Ref		GetLnPath(LPCHTTPENDPOINT ep);
	bool				ParseRequestRange(ULONGLONG total_size, ULONGLONG* offset, UINT* length) const;

	void				Send(LPCVOID p, int len, LPCSTR mime, UINT maxage_sec = 0);
	void				Send(LPCVOID p, int len, LPCSTR mime, ULONGLONG partial_from, ULONGLONG partial_to, ULONGLONG total_size);
	void				SendChuncked_Begin(LPCSTR mime, UINT maxage_sec = 0);
	void				SendChuncked(LPCVOID p, int len);
	void				SendChuncked(LPCSTR string){ SendChuncked(rt::String_Ref(string)); }
	void				SendChuncked(const rt::String_Ref& s){ if(!s.IsEmpty())SendChuncked(s.Begin(), (int)s.GetLength()); }
	void				SendChuncked(const rt::String& s){ if(!s.IsEmpty())SendChuncked(s.Begin(), (int)s.GetLength()); }
	template<typename t_StringExpr>
	void				SendChuncked(const t_StringExpr& s)
						{	int len = (int)s.GetLength();
							LPSTR buf = (LPSTR)alloca(len);
							VERIFY(len == s.CopyTo(buf));
							SendChuncked(buf, len);
						}
	void				SendChuncked_End();

	using HeaderField = std::unordered_map<rt::String_Ref, rt::String_Ref, rt::String_Ref::hash_compare>;
	void				SendHttpError(int http_status) {static const HeaderField extra_header; SendHttpError(http_status, extra_header);}
	void				SendHttpError(int http_status, const HeaderField& extra_header);
	void				SendRedirection(UINT code = HTTP_NOT_MODIFIED, LPCSTR url = nullptr, int url_len=0);

	void				SendJSONP_Begin();
	void				SendJSONP_End();
	void				SendJSONP_ArrayBegin();
	void				SendJSONP_ArrayEnd();
	void				SendJSONP_Empty();
	template<typename t_Json>
	void				SendJSONP_Object(const t_Json& x)
						{	int len = x.GetLength();
							if(__FirstJsonObject)
							{	__FirstJsonObject = false;
								LPSTR buf = (LPSTR)alloca(len);
								VERIFY(x.CopyTo(buf) == len);

								SendChuncked(buf, len);
							}
							else {
								LPSTR buf = (LPSTR)alloca(len+2);
								VERIFY(x.CopyTo(buf+2) == len);

								buf[0] = ','; buf[1] = '\n';
								SendChuncked(buf, len+2);
							}
						}
	void				SendJSON(const rt::String_Ref& x){ Send(x.Begin(), (int)x.GetLength(), "application/json; charset=utf-8"); }
	void				SendJSON(const rt::String& x){ SendJSON((const rt::String_Ref)x); }
	template<typename t_Json>
	void				SendJSON(const t_Json& x)
						{	int len = x.GetLength();
							LPSTR buf = (LPSTR)alloca(len);
							VERIFY(x.CopyTo(buf) == len);
							SendJSON(rt::String_Ref(buf, len));
						}
	SOCKET				TakeOver();		// socket will not be closed after request handling, httpd will leave it along
	void				Attach(SOCKET s){ _SocketAccepted.Attach(s); }
	LPBYTE				GetWorkSpace(UINT sz, bool preserve_existing_content = false);
};


template<class tDerived>
class HttpHandler:public HttpEndpoint
{
	struct _tDerived_wrap: public tDerived
	{	bool OnRequest(inet::HttpResponse& resp)
		{	return tDerived::OnRequest(resp); 
		}
	};
	static bool _endpoint_handler(HttpResponse* resp, HttpEndpoint* pThis){ return ((_tDerived_wrap*)pThis)->OnRequest(*resp); }
protected:
	virtual ~HttpHandler(){}
	HttpHandler(){ Handler = _endpoint_handler; }
};

class TinyHttpd
{
	volatile int __ConcurrencyCount;
protected:
	struct listening_port
	{
		TinyHttpd*	m_pHttpd;
		SOCKET		m_Socket;
		InetAddr	m_Address;
	};
	struct IncomingConnection
	{
		SOCKET socket;
		struct sockaddr_in	RemoteName;
		IncomingConnection() : socket(INVALID_SOCKET) 
		{
			rt::Zero(RemoteName);
		}
	};

	using IncomingConnQueue = ext::AsyncDataQueue<IncomingConnection, true, 32, false>;

	rt::Buffer<listening_port>	m_Listeners;
	rt::Buffer<os::Thread>		m_ListenThreads;
	rt::Buffer<os::Thread>		m_HandleThreads;

	uint32_t							m_PendingQueueMaxSize = 0;
	std::shared_ptr<IncomingConnQueue>	m_PendingIncomingConnection;
	void		_accept_handling_thread(listening_port& listener);
	void		_request_handling_thread();

	UINT		m_IOHangTimeout;
	UINT		m_Concurrency;
	bool		m_IsConcurrencyRestricted;
	
public:
	enum MimeType
	{	MIME_BINARY = 0,
		MIME_BMP,
		MIME_PNG,
		MIME_CSS,
		MIME_GIF,
		MIME_HTML,
		MIME_ICON,
		MIME_JPEG,
		MIME_JS,
		MIME_PDF,
		MIME_SVG,
		MIME_SWF,
		MIME_TIFF,
		MIME_TEXT,
		MIME_VRML,
		MIME_WAVE,
		MIME_ZIP,
		MIME_XML,
		MIME_JSON
	};

	static const LPCSTR MIME_STRING_BINARY;
	static const LPCSTR MIME_STRING_BMP;
	static const LPCSTR MIME_STRING_PNG;
	static const LPCSTR MIME_STRING_CSS;
	static const LPCSTR MIME_STRING_GIF;
	static const LPCSTR MIME_STRING_HTML;
	static const LPCSTR MIME_STRING_ICON;
	static const LPCSTR MIME_STRING_JPEG;
	static const LPCSTR MIME_STRING_JS;
	static const LPCSTR MIME_STRING_PDF;
	static const LPCSTR MIME_STRING_SVG;
	static const LPCSTR MIME_STRING_SWF;
	static const LPCSTR MIME_STRING_TIFF;
	static const LPCSTR MIME_STRING_TEXT;
	static const LPCSTR MIME_STRING_VRML;
	static const LPCSTR MIME_STRING_WAVE;
	static const LPCSTR MIME_STRING_ZIP;
	static const LPCSTR MIME_STRING_XML;
	static const LPCSTR MIME_STRING_JSON;

	static const LPCSTR	_MIMEs[19];
	static LPCSTR		_Ext2MIME(LPCSTR ext, int len);
	static LPCSTR		_GetMIME(const rt::String_Ref& filename);

	enum _tagHTTPRET
	{	HTTP_RECV_BLOCK = 1024,
		HTTP_SEND_BLOCK = 1024,
		HTTP_REQUEST_SIZEMAX = 100*1024*1024,
		HTTP_REQUEST_HEADER_SIZEMAX = 10*1024,
		HTTP_OK = 0,
		HTTP_FALSE = 1,
		HTTP_FAIL = -1,
		HTTP_OUTOFMEMORY = -2,
		HTTP_INVALIDARG = -3
	};
	class _Response:public HttpResponse
	{
		static UINT			_ConvertToUTF8(LPSTR pInOut, UINT len); ///< return converted length
	public:
		_Response();
		~_Response();
		void				Clear();
		bool				ExtendRecvBuf();
		int					GetBufRemain() const { return _RecvBufSize - _RecvBufUsed; }
		UINT				OnDataRecv(int newly_recv);
	public:
		LPSTR				_RecvBuf;
		UINT				_RecvBufSize;
		UINT				_RecvBufUsed;
		UINT				_RecvBufUsedExpected;
	};
protected:
	typedef rt::hash_map<rt::String_Ref,HttpEndpoint*> t_EndPoints;
	os::ThreadSafeMutable<t_EndPoints> _EndPoints;

public:
	TinyHttpd(void);
	~TinyHttpd(void);
	bool			Start(int port, int concurrency = 0, uint32_t queue_size = 0);	// bind to all local addresses
	bool			Start(const InetAddr& bind, int concurrency = 0, uint32_t queue_size = 0){ return Start(&bind, 1, concurrency, queue_size); }
	bool			Start(const InetAddr* pBindAddress, int address_count, int concurrency = 0, uint32_t queue_size = 0);
	void			ReplaceEndpoint(LPHTTPENDPOINT ep);
	bool			AddEndpoint(LPHTTPENDPOINT ep);			///< httpd will NOT manage the lifecycle of eps
	bool			SetEndpoints(LPHTTPENDPOINT* ep, UINT count); ///< httpd will NOT manage the lifecycle of eps
	void			SetConcurrencyRestricted(bool restricted = true);
	bool			IsRunning() const { return m_Listeners.GetSize(); }
	void			Stop();
	void			SetHangingTimeout(UINT msec = 10000){ m_IOHangTimeout = msec; }

	UINT			GetBindedAddresses(inet::InetAddr* pOut, UINT OutLen);	///< return # of InetAddr copied
	inet::InetAddr	GetBindedAddress() const;
	DWORD			GetBindedPort() const;
};

class HttpChunckedXMLWriter
{
	char			_Buf[TinyHttpd::HTTP_SEND_BLOCK];
	int				_BufUsed;
	HttpResponse&	_Response;
public:
	HttpChunckedXMLWriter(HttpResponse& r);
	~HttpChunckedXMLWriter();
	void Write(LPCVOID p, int len);
};

class HttpRequestEcho:public HttpHandler<HttpRequestEcho>
{
public:
	bool	OnRequest(HttpResponse& resp);
};
/** @}*/
} // inet
/** @}*/