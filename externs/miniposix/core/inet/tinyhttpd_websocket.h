#pragma once
#include "../ext/botan/botan.h"
#include "tinyhttpd.h"

namespace inet
{

class WebSocketSvc:public HttpHandler<WebSocketSvc>	// Websocket/HTML5 message pusher
{
public:
	enum _tagWSVerion
	{	
		WSVER_UNKNOWN	= 0x0,
		WSVER_RFC6455	= 13,	// RFC 6455 - The value of Sec-WebSocket-Version header field MUST be 13
		WSVER_MASKBITS	= 0xff
	};
	enum _tagWSOpCode
	{
		WSOP_CONTINUATION = 0,
		WSOP_BEGIN_TEXT = 1,
		WSOP_BEGIN_BINARY = 2,
		WSOP_BYEBYE = 8,
		WSOP_PING = 9,
		WSOP_PONG = 10,
		WSOP_MASK = 0xf,

		WSOP_FLAG_MSGFIN = 0x80,
		WSOP_FLAG_PAYLOAD_MASKED = 0x80,
	};
protected:
	enum _tagStatusCodes : uint16_t // rfc 6455 Status codes
	{
		WSSC_NORMAL				= 1000,
		WSSC_GOING_AWAY			= 1001,
		WSSC_PROTOCOL_ERROR		= 1002,
		WSSC_UNSUPPORTED_DATA	= 1003,
	};

	static const int32_t	SIZE_SENDINGBUFFER = 100*1024;
	static const int32_t	SIZE_CHUNKBUFFER = 1024;

#pragma pack(1)
	struct SendingBlockHeader
	{
		uint32_t	TopicIndex;	// INFINITE for all Subscribers
		int32_t		Head_RFC6455;
		int32_t		Head_RFC6455_Skip;
	};
	struct SendingBlock:public SendingBlockHeader
	{	
		////Common Data Framing
		////	[BYTE-4][Payload][BYTE-1] = FrameData
		////	actually data to be sent:   FrameData[Head_XX_Skip] to FrameData[4+Payload_len]
		union
		{	uint8_t		FrameData[1];
			struct
			{	int32_t	Header;
				BYTE	Payload[1];
			};
		};
	};
	/*
	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-------+-+-------------+-------------------------------+
	|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
	|N|V|V|V|       |S|             |   (if payload len==126/127)   |
	| |1|2|3|       |K|             |                               |
	+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	|     Extended payload length continued, if payload len == 127  |
	+ - - - - - - - - - - - - - - - +-------------------------------+
	|                               |Masking-key, if MASK set to 1  |
	+-------------------------------+-------------------------------+
	| Masking-key (continued)       |          Payload Data         |
	+-------------------------------- - - - - - - - - - - - - - - - +
	:                     Payload Data continued ...                :
	+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	|                     Payload Data continued ...                |
	+---------------------------------------------------------------+
	*/
	struct WS_Frame
	{
		uint8_t		fin_opcode;
		uint8_t		mask_payload_len;
		bool 		IsFin(){ return fin_opcode & WSOP_FLAG_MSGFIN; }
		bool 		IsMasked(){ return mask_payload_len & WSOP_FLAG_PAYLOAD_MASKED; }
	};
	struct WS_ControlFrame: public WS_Frame
	{
		uint16_t	Param;
	};
	struct WS_FullFrame: public WS_Frame
	{	
		uint16_t	payload_length_short;
		int32_t		payload_length_long;
		uint16_t	payload_length_longLow;
		int32_t		mask_key;	// present when masked == 1

		uint32_t	Setup(uint8_t opcode, uint64_t payload_len, uint32_t payload_mask = 0); // return size of header
		void		GetPayloadPosition(uint64_t& length, uint32_t& Offset) const;
		LPBYTE		UnmaskPayload(uint32_t length, uint32_t offset);
	};
#pragma pack()

public:
	class Connection
	{	
		friend class WebSocketSvc;
		enum{ FRAME_RECV_BLOCK = 1024 };
		enum{ FRAME_LENGTH_MAX = 10*1024*1024 };

		uint32_t				_Flag;
		SOCKET					_Socket;
		WebSocketSvc*			_pSvc;
		os::Thread				_RecvThread;
		volatile int			_IORefCount;
		os::CriticalSection		_SendCS;
		void					_RecvWorker();
		void					_StartReceiving();
		void					_Disconnect();
		bool					_SendFrame(const WS_Frame* frame, uint32_t framesize);

		Connection(SOCKET s, int WS_ver, WebSocketSvc* svc);
		~Connection(){ ASSERT(_IORefCount==0); ASSERT(!_RecvThread.IsRunning()); }
	public:
		bool					IsEmpty() const { return _Socket == INVALID_SOCKET && _IORefCount == 0; }
		bool					IsStopped() const { return !_RecvThread.IsRunning(); }
		int32_t					GetWSVersion() const { return _Flag&WSVER_MASKBITS; }
		bool					SendControl(int opcode); // WSOP_BYEBYE
		bool					SendData(const rt::String_Ref& data);
		void					AddIORef(){ os::AtomicIncrement(&_IORefCount); }
		void					ReleaseIORef(){ os::AtomicDecrement(&_IORefCount); }
	};

protected:
	rt::CircularBuffer	_PushBuffer;
	os::CriticalSection	_PushBufferCS;
	volatile uint32_t	_PushTopicIndexNext;
	os::Event			_NewPushing;
	os::Thread			_PushThread;
	void				_PushWorker();
	void				_SendSocketData(Connection* conn, SendingBlock* sb, int32_t payloadsize);
	bool				_SendPushFrame(uint32_t topic_index, int32_t opcode, LPCBYTE data1, uint32_t len1, LPCBYTE data2, uint32_t len2);

	LPBYTE				_PushSendBuffer_Begin(uint32_t topic_index, uint32_t opcode, uint32_t payloadsize);
	void				_PushSendBuffer_End(LPCVOID pBlock, uint32_t framesize_finalized);

protected:
	os::CriticalSection			_ConnectionsCS; // protect _Subscriptions and _Connections
	rt::BufferEx<Connection*>	_Connections;
	std::unordered_map<uint32_t, rt::BufferEm<Connection*>>	_Subscriptions; // TopicIndex => Connection

public:
	WebSocketSvc();
	~WebSocketSvc();
	void				Create(HttpEndpoint* fallback = nullptr);
	bool				IsCreated() const { return _PushThread.IsRunning(); }
	void				Destory();

	uint32_t			AllocatePushTopic();
	void				SubscribePushTopic(uint32_t topic_index, Connection* conn);

	bool				Push(const void* p, uint32_t len, uint32_t topic_index); // len < 64KB
	bool				OnRequest(HttpResponse& resp);

public:	// events
	THISCALL_POLYMORPHISM_DECLARE(bool, true, OnConnecting, Connection* p);
	THISCALL_POLYMORPHISM_DECLARE_VOID(OnDisconnected, Connection* p);
	THISCALL_POLYMORPHISM_DECLARE_VOID(OnMessage, Connection* p, LPSTR msg, int32_t len);

	void SetOnDataCallback(LPVOID obj, const THISCALL_MFPTR& on_connecting = nullptr, const THISCALL_MFPTR& on_disconnected = nullptr, const THISCALL_MFPTR& on_message = nullptr);

protected:
	THISCALL_MFPTR	_OnConnecting;
	THISCALL_MFPTR	_OnDisconnected;
	THISCALL_MFPTR	_OnMessage;
	LPVOID			_EventHandlerCookie = nullptr;
	HttpEndpoint*	_pFallbackHandler = nullptr;  // invoke for request rather than upgrade
};

} // namespce inet