#include "tinyhttpd_websocket.h"

namespace inet
{

WebSocketSvc::WebSocketSvc()
{
	_PushBuffer.SetSize(SIZE_SENDINGBUFFER);
	_OnConnecting.Zero();
	_OnDisconnected.Zero();
	_OnMessage.Zero();
}

void WebSocketSvc::Connection::_Disconnect()
{
	if(!_pSvc->_OnDisconnected.IsNull())
		THISCALL_POLYMORPHISM_INVOKE(OnDisconnected, _pSvc->_EventHandlerCookie, _pSvc->_OnDisconnected, this);

	SOCKET s = _Socket;
	_Socket = INVALID_SOCKET;
	_RecvThread.WantExit() = true;
	Socket(s).Close();
}

bool WebSocketSvc::Connection::_SendFrame(const WS_Frame* frame, uint32_t framesize)
{
	bool sent;
	{	EnterCSBlock(_SendCS);
		sent = send(_Socket, (const char*)frame, framesize, 0) == framesize;
	}

	if(!sent)_Disconnect();
	return sent;
}

WebSocketSvc::Connection::Connection(SOCKET s, int WS_ver, WebSocketSvc* svc)
{
	_Flag = WSVER_RFC6455;
	_Socket = s;
	_IORefCount = 0;
	_pSvc = svc;
}

void WebSocketSvc::Connection::_StartReceiving()
{
	struct _call
	{	static DWORD _func(LPVOID x)
		{	((Connection*)x)->_RecvWorker();
			return 0;
		}
	};

	VERIFY(_RecvThread.Create(_call::_func, this));
}

bool WebSocketSvc::Connection::SendControl(int opcode)
{
	switch(GetWSVersion())
	{
	case WSVER_RFC6455:
		{
			uint8_t payloadsize = 0;
			if(opcode == WSOP_BYEBYE)payloadsize = 2;
			ASSERT(opcode >=WSOP_BYEBYE && opcode <=WSOP_PONG);

			WS_ControlFrame frame = { (uint8_t)(opcode|WSOP_FLAG_MSGFIN), payloadsize, htons(WSSC_NORMAL) };
			bool ret = _SendFrame(&frame, payloadsize + sizeof(frame) + payloadsize);
			if(opcode == WSOP_BYEBYE)_Disconnect();
			return ret;
		}
	default: ASSERT(0);
	}

	return false;
}

bool WebSocketSvc::Connection::SendData(const rt::String_Ref& data)
{
	bool sent = false;
	switch(GetWSVersion())
	{
	case WSVER_RFC6455:
		{
			WS_FullFrame frame;
			uint32_t header_size = frame.Setup(WSOP_BEGIN_TEXT|WSOP_FLAG_MSGFIN, data.GetLength());

			
			{	EnterCSBlock(_SendCS);
				sent =	send(_Socket, (const char*)&frame, header_size, 0) == header_size &&
						send(_Socket, data.Begin(), data.GetLength(), 0) == data.GetLength();
			}
		}
		break;
	default: ASSERT(0);
	}

	if(!sent)_Disconnect();
	return sent;
}

void WebSocketSvc::_SendSocketData(Connection* conn, SendingBlock* sb, int32_t payloadsize)
{
	int32_t framesize = 0;
	int32_t bytesend = -1;
	switch(conn->GetWSVersion())
	{
		case WSVER_RFC6455:
			{	sb->Header = sb->Head_RFC6455;
				framesize = payloadsize + 4 - sb->Head_RFC6455_Skip;
				WS_Frame* f = (WS_Frame*)&sb->FrameData[sb->Head_RFC6455_Skip];
				conn->_SendFrame(f, framesize);
				break;
			}
		default: ASSERT(0);
	}
}

void WebSocketSvc::_PushWorker()
{
	rt::BufferEx<Connection*> multi_cast;

	for(;;)
	{
		_NewPushing.WaitSignal();
		_NewPushing.Reset();

		const rt::CircularBuffer::Block* p;
		{	EnterCSBlock(_PushBufferCS);
			p = _PushBuffer.Peek();
			if(!p)continue;
		}

		while(p)
		{
			if(_PushThread.WantExit())return;

			uint32_t payloadsize;
			SendingBlock*	sb = (SendingBlock*)p->Data;
			multi_cast.ShrinkSize(0);

			{	EnterCSBlock(_ConnectionsCS);
				auto it = _Subscriptions.find(sb->TopicIndex);
				if(it == _Subscriptions.end() || !it->second.GetSize())
					goto NEXT_SEND_BLOCK;

				for(auto c : it->second)
				{
					if(!c->IsEmpty())
					{
						multi_cast.push_back(c);
						c->AddIORef();
					}
				}
			}

			payloadsize = (int32_t)(p->Length - sizeof(SendingBlockHeader) - 4);
			for(auto c : multi_cast)
			{
				_SendSocketData(c, sb, payloadsize);
				c->ReleaseIORef();
			}

NEXT_SEND_BLOCK:
			{	EnterCSBlock(_PushBufferCS);
				_PushBuffer.Pop();
				p = _PushBuffer.Peek();
			}
		}
	}
}

WebSocketSvc::~WebSocketSvc()
{
	Destory();
}

bool WebSocketSvc::OnRequest(HttpResponse& resp)
{
	//	 GET /chat HTTP/1.1
    //   Host: server.example.com
    //   Upgrade: websocket
    //   Connection: Upgrade
    //   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
    //   Origin: http://example.com
    //   Sec-WebSocket-Protocol: chat, superchat
    //   Sec-WebSocket-Version: 13

	rt::String_Ref	upgrade = resp.GetHeaderField("Upgrade:");
	rt::String_Ref	connection = resp.GetHeaderField("Connection:");

	upgrade.MakeLower();
	connection.MakeLower();

	if(upgrade == "websocket" && connection.FindString(rt::String_Ref("upgrade",7))>=0)
	{
		rt::String_Ref seckey = resp.GetHeaderField("Sec-WebSocket-Key:");
		rt::String_Ref version =  resp.GetHeaderField("Sec-WebSocket-Version:");

		Connection* new_conn = nullptr;
		if((!seckey.IsEmpty() && seckey.GetLength() <= 256 && !version.IsEmpty()))
		{	
			uint32_t ver = WSVER_UNKNOWN;
			version.ToNumber(ver);
			if(ver != WSVER_RFC6455)
			{
				static const HttpResponse::HeaderField header = {{"Sec-WebSocket-Version", "13"}};
				resp.SendHttpError(HTTP_BAD_REQUEST, header);
				return true;
			}

			new_conn = _New(Connection(resp, WSVER_RFC6455, this));
			if(!_OnConnecting.IsNull())
				if(THISCALL_POLYMORPHISM_INVOKE(OnConnecting, _EventHandlerCookie, _OnConnecting, new_conn))
					goto SUBSCRIBERS_ACCEPTED;

			resp.SendHttpError(HTTP_NOT_ALLOWED);
		}
		else
		{
			resp.SendHttpError(HTTP_BAD_REQUEST);
		}

		_SafeDel(new_conn);
		return true;

SUBSCRIBERS_ACCEPTED:
		// send ack back
		//	HTTP/1.1 101 Switching Protocols
		//	Upgrade: websocket
		//	Connection: Upgrade
		//	Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
		//	Sec-WebSocket-Protocol: chat

		static const char header[] =	//"HTTP/1.1 101 Switching Protocols\r\n"
										"HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
										"Upgrade: WebSocket\r\n"
										"Connection: Upgrade\r\n";
										//"Sec-WebSocket-Protocol: chat\r\n";
		static const char newline2[] = "\r\n\r\n";

		rt::OStreamFixed<1024>	buf;
		buf.Write(header,sizeof(header)-1);

		{	rt::String_Ref orign = resp.GetHeaderField("Origin:");
			if(!orign.IsEmpty())
			{	static const char ws_host[] = "Sec-WebSocket-Origin: ";
				buf.Write(ws_host, sizeof(ws_host)-1);
				buf.Write(orign.Begin(),(uint32_t)orign.GetLength());
				buf.Write(newline2,2);
			}
		}

		{	rt::String_Ref host = resp.GetHeaderField("Host:");
			if(!host.IsEmpty())
			{	static const char ws_host[] = "Sec-WebSocket-Location: ws://";
				buf.Write(ws_host, sizeof(ws_host)-1);
				buf.Write(host.Begin(),(uint32_t)host.GetLength());
				buf.Write(resp.URI.Begin(),(uint32_t)resp.URI.GetLength());
				buf.Write(newline2,2);
			}
		}
		
		/*
		GET /evt?channel=log HTTP/1.1
		Upgrade: websocket
		Connection: Upgrade
		Host: 10.0.0.15:10003
		Origin: http://10.0.0.15:10003
		Sec-WebSocket-Key: cSjRdnLdJuWpy3DaPoW9IQ==
		Sec-WebSocket-Version: 13
		Sec-WebSocket-Extensions: x-webkit-deflate-frame
		
		
		OnDataRecv = 0
		SHA1 shakehand
		HTTP/1.1 101 Web Socket Protocol Handshake
		Upgrade: WebSocket
		Connection: Upgrade
		Sec-WebSocket-Origin: http://10.0.0.15:10003
		Sec-WebSocket-Location: ws://10.0.0.15:10003/evt
		Sec-WebSocket-Accept: Pyus1Ef2etg0GS/1U3Zgb/TJCBQ=
		*/

		static constexpr char sign[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		static constexpr char swa[] = "Sec-WebSocket-Accept: "; //s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

		BYTE sha1[20];
		{
			rt::String data = seckey + sign;
			sec::Hash<sec::HASH_SHA1>().Calculate(data.Begin(), data.GetLength(), sha1);
		}

		buf.Write(swa, sizeof(swa) - 1);

		int32_t acklen = os::Base64EncodeLength(20);
		int32_t orgslen = (int32_t)buf.GetLength();
		buf.SetLength((uint32_t)buf.GetLength() + acklen);
		os::Base64Encode(((LPSTR)buf.GetInternalBuffer()) + orgslen, sha1, 20);
		buf.Seek(0, rt::_File::Seek_End);
		buf.Write(newline2, 4);

		send(resp,(LPSTR)buf.GetInternalBuffer(), (int32_t)buf.GetLength(),0);
		//_LOG(rt::String_Ref((LPSTR)buf.GetInternalBuffer(), (int32_t)buf.GetLength()));
		//_LOG("LEN = "<<buf.GetLength());
		resp.TakeOver();	// prevent the connection to be closed by httpd

		{	Connection* to_be_del[16];
			uint32_t to_be_del_count = 0;

			new_conn->_StartReceiving();

			{	EnterCSBlock(_ConnectionsCS);
				uint32_t remain = 0;
				for(uint32_t i=0; i<_Connections.GetSize(); i++)
				{
					if(_Connections[i]->IsEmpty() && _Connections[i]->IsStopped())
					{
						to_be_del[to_be_del_count++] = _Connections[i];
						if(to_be_del_count == sizeofArray(to_be_del))break;
						//_SafeDel(_Connections[i]);
					}
					else
					{
						_Connections[remain++] = _Connections[i];
					}
				}

				_Connections.ShrinkSize(remain);
				_Connections.push_back(new_conn);

				for(auto& it : _Subscriptions)
				{
					for(uint32_t d = 0; d<to_be_del_count; d++)
						it.second.Remove(to_be_del[d]);
				}

				for(uint32_t d = 0; d<to_be_del_count; d++)
					_SafeDel_ConstPtr(to_be_del[d]);
			}
		}
	}
	else if(_pFallbackHandler)
		_pFallbackHandler->HandleRequest(&resp);
	else
		resp.SendHttpError(HTTP_FORBIDDEN);

	return true;
}

uint32_t WebSocketSvc::AllocatePushTopic()
{
	return (uint32_t)os::AtomicIncrement((volatile int*)&_PushTopicIndexNext);
}

void WebSocketSvc::SubscribePushTopic(uint32_t topic_index, Connection* conn)
{
	EnterCSBlock(_ConnectionsCS);
	auto& list = _Subscriptions[topic_index];
	if(list.Find(conn) < 0)
		list.push_back(conn);
}

LPBYTE WebSocketSvc::_PushSendBuffer_Begin(uint32_t topic_index, uint32_t opcode, uint32_t payloadsize)
{
	ASSERT(payloadsize <= 0xffff);
	_PushBufferCS.Lock();
	SendingBlock* p = (SendingBlock*)_PushBuffer.Push(payloadsize + sizeof(SendingBlockHeader) + 4);

	if(p)
	{
		p->TopicIndex = topic_index;
		p->Head_RFC6455 = opcode;

		return p->Payload;
	}
	else
	{	_PushBufferCS.Unlock();	
		return NULL;
	}
}

void WebSocketSvc::_PushSendBuffer_End(LPCVOID pBlock, uint32_t payloadsize)
{
	SendingBlock* p = (SendingBlock*)(((LPCBYTE)pBlock) - sizeof(SendingBlockHeader) - 4);

	int32_t opcode = p->Head_RFC6455;

	WS_FullFrame* ws;
	if(payloadsize >= 126)
	{
		ws = (WS_FullFrame*)&p->Head_RFC6455;
		ws->mask_payload_len = 126;
		ws->payload_length_short = htons(payloadsize);
		p->Head_RFC6455_Skip = 0;
	}
	else
	{	ws = (WS_FullFrame*)(2 + (LPBYTE)&p->Head_RFC6455);
		ws->mask_payload_len = payloadsize;
		p->Head_RFC6455_Skip = 2;
	}
	ws->fin_opcode = opcode;

	_PushBuffer.SetBlockSize(p,payloadsize + sizeof(SendingBlockHeader) + 4);

	_PushBufferCS.Unlock();
	_NewPushing.Set();
}

bool WebSocketSvc::_SendPushFrame(uint32_t topic_index, int32_t opcode_fin, LPCBYTE data1, uint32_t len1, LPCBYTE data2, uint32_t len2)
{
	int32_t len = len1 + len2;
	ASSERT(len <= 0xffff);

	LPBYTE pl = _PushSendBuffer_Begin(topic_index, opcode_fin, len);
	memcpy(pl,data1,len1);
	if(len2)memcpy(pl+len1,data2,len2);
	_PushSendBuffer_End(pl,len);

	return true;
}

bool WebSocketSvc::Push(const void* p, uint32_t len, uint32_t topic_index)
{
	LPCBYTE data = (LPCBYTE)p;

	int32_t opcode = WSOP_BEGIN_TEXT;
	for(;;)
	{
		if(SIZE_CHUNKBUFFER < len)
		{
			if(!_SendPushFrame(topic_index, opcode, data, SIZE_CHUNKBUFFER, NULL, 0))return false;
			data += SIZE_CHUNKBUFFER;
			len -= SIZE_CHUNKBUFFER;
			opcode = WSOP_CONTINUATION;
		}
		else
		{	// last frame
			return _SendPushFrame(topic_index, opcode|WSOP_FLAG_MSGFIN,data,len,NULL,0);
		}
	}
}

void WebSocketSvc::WS_FullFrame::GetPayloadPosition(uint64_t& length, uint32_t& offset) const
{
	int32_t payload_len = mask_payload_len&0x7f;
	if(payload_len < 126)
	{	
		length = payload_len;
		offset = 2;
	}
	else if(payload_len == 126)
	{
		length = ntohs(payload_length_short);
		offset = 4;
	}
	else if(payload_len == 127)
	{
		length = (((uint64_t)ntohs(payload_length_short))<<48) | 
				 (((uint64_t)ntohl(payload_length_long))<< 16) |
				 ntohs(payload_length_longLow);
		offset = 10;
	}
	
	if(mask_payload_len&WSOP_FLAG_PAYLOAD_MASKED)offset += 4;
}

uint32_t WebSocketSvc::WS_FullFrame::Setup(uint8_t opcode, uint64_t payload_len, uint32_t payload_mask)
{
	fin_opcode = opcode;

	uint32_t ret;
	if(payload_len < 126)
	{
		mask_payload_len = payload_len;
		ret = 2;
	}
	else if(payload_len <= 0xffffff)
	{
		mask_payload_len = 126;
		payload_length_short = ntohs(payload_len);
		ret = 4;
	}
	else
	{
		mask_payload_len = 127;
		payload_length_short = ntohs(payload_len>>48);
		payload_length_long = ntohl(payload_len>>16);
		payload_length_longLow = ntohs(payload_len);
		ret = 10;
	}

	if(payload_mask)
	{
		mask_payload_len |= WSOP_FLAG_PAYLOAD_MASKED;
		*(uint32_t*)(((char*)this) + ret) = payload_mask;
		ret += 4;
	}

	return ret;
}

LPBYTE WebSocketSvc::WS_FullFrame::UnmaskPayload(uint32_t length, uint32_t offset)
{
	LPBYTE pld = ((LPBYTE)this) + offset;
	if(mask_payload_len&WSOP_FLAG_PAYLOAD_MASKED)
	{
		LPBYTE mask = pld - 4;
		for(uint32_t i=0;i<length;i++)
			pld[i] = pld[i] ^ mask[i&0x3];
	}
	return pld;
}

void WebSocketSvc::Create(HttpEndpoint* fallback)
{
	ASSERT(_Connections.GetSize() == 0);

	struct _func
	{	static DWORD _call(LPVOID p)
		{	((WebSocketSvc*)p)->_PushWorker();
			return 0;
		}
	};

	_PushTopicIndexNext = 0;
	_pFallbackHandler = fallback;

	_NewPushing.Reset();
	_PushThread.Create(_func::_call,this);
}

void WebSocketSvc::Destory()
{
	_pFallbackHandler = nullptr;
	_Subscriptions.clear();

	if(_PushThread.IsRunning())
	{	
		_PushThread.WantExit() = true;
		_NewPushing.Set();

		_PushThread.WaitForEnding();

		EnterCSBlock(_PushBufferCS);
		_PushBuffer.Empty();
	}

	{	EnterCSBlock(_ConnectionsCS);
		_Subscriptions.clear();

		for(auto s : _Connections)
		{
			s->_RecvThread.WantExit() = true;
			Socket(s->_Socket).Close();
			s->_Socket = INVALID_SOCKET;

			if(!_OnDisconnected.IsNull())
				THISCALL_POLYMORPHISM_INVOKE(OnDisconnected, _EventHandlerCookie, _OnDisconnected, s);
		}

		for(auto* s : _Connections)
		{
			s->_RecvThread.WaitForEnding();
			_SafeDel_ConstPtr(s);
		}

		_Connections.ShrinkSize(0);
	}
}

void WebSocketSvc::Connection::_RecvWorker()
{
	rt::OStream	frame;
	switch(GetWSVersion())
	{
	case WSVER_RFC6455:
		{
			int32_t data_recved = 0;
			int32_t frame_len = FRAME_LENGTH_MAX + 1;
		
			if(frame.GetLength() - data_recved < FRAME_RECV_BLOCK)frame.SetLength(data_recved + FRAME_RECV_BLOCK);
			int32_t newrecv = 0;
			while((newrecv = recv(_Socket,(LPSTR)frame.GetInternalBuffer() + data_recved,FRAME_RECV_BLOCK,0))>0)
			{
				data_recved += newrecv;

				bool state_changed = true;
				while(state_changed)
				{	
					state_changed = false;
					if(data_recved >= frame_len)
					{
						// a frame is received
						WS_FullFrame& ws = *(WS_FullFrame*)frame.GetInternalBuffer();
						int32_t opcode = ws.fin_opcode & WSOP_MASK;
						if(opcode == WSOP_PING)
						{	// Send WSOP_PONG
							//_Log("<<<["<<_Index<<"] Ping\n");
							SendControl(WSOP_PONG);
						}
						else if(opcode == WSOP_BYEBYE)
						{	// Send WSOP_BYEBYE
							//_Log("<<<["<<_Index<<"] BYE\n");
							SendControl(WSOP_BYEBYE);
							return;
						}
						else // Callback: OnDataFrameReceived
						{	ULONGLONG len;
							uint32_t offset;
							ws.GetPayloadPosition(len,offset);
							if(len)
							{	LPSTR msg = (LPSTR)ws.UnmaskPayload((uint32_t)len,offset);
								if(!_pSvc->_OnMessage.IsNull())
									THISCALL_POLYMORPHISM_INVOKE(OnMessage, _pSvc->_EventHandlerCookie, _pSvc->_OnMessage, this, msg, (int32_t)len);
							}
						}

						// prepare for next frame
						if(data_recved > frame_len)
							memcpy(frame.GetInternalBuffer(), frame.GetInternalBuffer() + frame_len, data_recved - frame_len);

						data_recved -= frame_len;
						frame_len = FRAME_LENGTH_MAX + 1;

						state_changed = true;
					}
			
					if(frame_len>FRAME_LENGTH_MAX && data_recved>=2)
					{
						// analysis frame
						WS_FullFrame& ws = *(WS_FullFrame*)frame.GetInternalBuffer();
						if(!ws.IsMasked()) goto CONNECTION_ENDED; // reject the connection
						
						ULONGLONG plen;
						uint32_t poff;
						ws.GetPayloadPosition(plen,poff);
						if((int32_t)poff <= data_recved)
						{
							if(plen + poff > FRAME_LENGTH_MAX)goto CONNECTION_ENDED; // reject the connection

							frame_len = (int32_t)(poff + plen);
							if((int32_t)frame.GetLength() < frame_len + FRAME_RECV_BLOCK)frame.SetLength(frame_len + FRAME_RECV_BLOCK);

							state_changed = true;
						}
					}
				}
			}
			break;
		}
		default: ASSERT(0);
	}

CONNECTION_ENDED:
	SendControl(WSOP_BYEBYE);
}

void WebSocketSvc::SetOnDataCallback(LPVOID obj, const THISCALL_MFPTR& on_connecting, const THISCALL_MFPTR& on_disconnected, const THISCALL_MFPTR& on_message)
{
	_EventHandlerCookie = obj;
	_OnConnecting = on_connecting;
	_OnDisconnected = on_disconnected;
	_OnMessage = on_message;
}

} // namespace inet