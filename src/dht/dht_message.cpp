#include "dht_message.h"
#include "dht_space.h"
#include "dht.h"


namespace upw
{

DWORD DhtMessageCompose::_AppTag = DHT_APP_TAG_DEFAULT;
DWORD DhtMessageCompose::_DhtVer = DHT_VERSION_DEFAULT;

void MainlineDHT::SetMessageVersionTags(LPCSTR dht_ver, LPCSTR app_tag)
{
	struct _sub: public DhtMessageCompose
	{
		static void set(LPCSTR dht_ver, LPCSTR app_tag)
		{
			if(app_tag)
			{
				ASSERT(strlen(app_tag) == 4);
				_AppTag = *(DWORD*)app_tag;
			}

			if(dht_ver)
			{
				ASSERT(strlen(dht_ver) == 4);
				_DhtVer = *(DWORD*)dht_ver;
			}
		}
	};

	_sub::set(dht_ver, app_tag);
}

void DhtNodeBase::UpdateLatency(float latency)
{
	if(latency>= -rt::TypeTraits<float>::Epsilon())
	{
		if(latency_average >= 0)
		{	
			if(latency > latency_average)
			{
				float n = (latency + DHT_LATENCY_SMOOTHING_FACTOR*latency_average)/(1+DHT_LATENCY_SMOOTHING_FACTOR);
				latency_average = rt::min(latency_average + rt::max(0.05f, latency_average*0.2f), n);
			}
			else if(latency > latency_average/3)
			{	
				latency_average = (latency + DHT_LATENCY_SMOOTHING_FACTOR*latency_average)/(1+DHT_LATENCY_SMOOTHING_FACTOR);
			}
			else
			{	latency_average = (latency + latency_average)/2;
			}
		}
		else
			latency_average = latency;
	}
}

bool DhtMessageParse::ParsePacket(const recv_data& rd, bool bViaIpv4 /* = true */)
{
	LPCSTR msg = rd.msg;
	UINT   len = rd.msg_len;

	if(msg[0] != 'd' || len < 14 || msg[len-1] != 'e')return false;

	LPCSTR end = msg + len-1;
	msg ++;

	int level = 0;
	char path_initial[16];

	fields_parsed = 0;
	cip_v4 = nullptr;
	swarm_member = false;
	leaving_by_ping = false;
	bool implied_port = false;

	while(msg < end)
	{
		// level up
		if(msg[0] == 'e')
		{	if(level>0)
			{	level--;
				path_initial[level] = 0;
				msg++;
				continue;
			}
			else{ return false; }
		}

		// parse key
		int keylen = 0;
		LPCSTR key;
		{	int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(keylen);
			if(eta == 0 || keylen == 0 || msg[eta] != ':')
				return false;
			key = msg + eta + 1;
		}
		msg = key + keylen;
		if(msg >= end)
			return false;

		// parse value
		if(msg[0]>='0' && msg[0]<='9')
		{
			int vallen = 0;
			LPCSTR val;
			{	int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(vallen);
				if(eta == 0 || msg[eta] != ':')
					return false;
				val = msg + eta + 1;
			}
			msg = val + vallen;

			// got a string
			//_LOGC('L'<<level<<'\t'<<path_initial<<'/'<<rt::String_Ref(key,keylen)<<':'<<rt::String_Ref(val, vallen));

			//////////////////////////////////////////////////////////////////
			// Parsing field specific to BT-DHT
			if(level == 0)
			{
				switch(keylen)
				{
				case 1:
					switch(key[0]) // parse t, y, q
					{
					case 't':	// transcation token
						if(DHT_MESSAGE_TRANSCATIONID_MAXLEN<vallen)
							return false;
						query_transId = val;
						query_transId_length = vallen;
						fields_parsed |= MSGFIELD_TRANSID;
						break;
					case 'y':
						if(vallen != 1)
							return false;
						y = val[0];
						fields_parsed |= MSGFIELD_Y;
						break;
					case 'q':
						if(vallen<4)
							return false;
						q = *((DWORD*)val);
						fields_parsed |= MSGFIELD_Q;
						break;
					case 'v':
						if(vallen>=2)
						{	version_length = vallen;
							version = val;
							fields_parsed |= MSGFIELD_PEER_VERSION;
						}
						break;
					}
					break;
				case 2:
					if(*((WORD*)key) == 0x7069) // ip
					{
						if(vallen == 6)
						{
							fields_parsed |= MSGFIELD_EXTERNAL_IPV4;
							reply_extern_ip_v4 = *((IPv4*)val);
						}
						else if(vallen == 18) // ipv6
						{
							fields_parsed |= MSGFIELD_EXTERNAL_IPV6;
							reply_extern_ip_v6 = *((IPv6*)val);
						}
						else if(vallen == 4) // but not port
						{
							fields_parsed |= MSGFIELD_EXTERNAL_IPV4;
							reply_extern_ip_v4.IP = *((DWORD*)val);
							reply_extern_ip_v4.SetPort(0);
						}
						else if(vallen == 16)
						{
							fields_parsed |= MSGFIELD_EXTERNAL_IPV6;
							reply_extern_ip_v6 = *((IPv6*)val);
							reply_extern_ip_v6.SetPort(0);
						}
					}
					else if(*((WORD*)key) == 0x646e && vallen >= sizeof(NetworkPeerDesc)) // nd
					{
						if(msg >= end)
							return false;
						fields_parsed |= MSGFIELD_NODEDESC;
						memcpy(&node_desc, val, sizeof(NetworkNodeDesc));
					}
					break;
				case 3:
					if((*((DWORD*)key) & 0xffffff) == 0x707061 && vallen == 4) // app
					{
						fields_parsed |= MSGFIELD_APPTAG;
						app_tag = *(DWORD*)val;
					}
					break;
				case 4:
					if((*((DWORD*)key)) == 0x6e707370 && vallen == 8) // pspn
					{
						fields_parsed |= MSGFIELD_PRIVATESWARM_PNUM;
						private_swarm_packet_num = *(ULONGLONG*)val;
					}
					else if((*((DWORD*)key)) == 0x34706963 && vallen == sizeof(CloakedIPv4) && (fields_parsed&MSGFIELD_CLOAK_IPV6) == 0) // cip4
					{
						fields_parsed |= MSGFIELD_CLOAK_IPV4;
						cip_v4 = (CloakedIPv4*)val;
					}
					else if((*((DWORD*)key)) == 0x36706963 && vallen == sizeof(CloakedIPv6) && (fields_parsed&MSGFIELD_CLOAK_IPV4) == 0) // cip6
					{
						fields_parsed |= MSGFIELD_CLOAK_IPV6;
						cip_v6 = (CloakedIPv6*)val;
					}
					break;
				case 5:
					if(*((DWORD*)key) == 0x69746c61 && key[4] == 'p') // altip
					{
						if(vallen == 6 && !bViaIpv4)
						{
							fields_parsed |= MSGFIELD_ALTERNATIVE_IPV4;
							alternative_ip_v4 = *((IPv4*)val);
						}
						else if(vallen == 18 && bViaIpv4) // ipv6
						{
							fields_parsed |= MSGFIELD_ALTERNATIVE_IPV6;
							alternative_ip_v6 = *((IPv6*)val);
						}
					}
					else if(*((DWORD*)key) == 0x7661656c && key[4] == 'e' && vallen == 1) // leave
					{
						leaving_by_ping = (val[0] == '1' || val[0] == 1);
					}
					break;
				}
			}
			else if(level == 1)
			{	
				if(	*((WORD*)key) == 0x6469 && keylen == 2 && // id
					vallen == DHT_ADDRESS_SIZE &&
					(path_initial[0] == 'a' || path_initial[0] == 'r')
				)	// fields: r/id or a/id
				{
					if(msg >= end)
						return false;
					memcpy(a_id.addr, val, DHT_ADDRESS_SIZE);
					fields_parsed |= (path_initial[0] == 'a')?MSGFIELD_A_ID:MSGFIELD_R_ID;
				}
				else
				if(	*((DWORD*)key) == 0x67726174 && *((WORD*)(key+4)) == 0x7465 && keylen == 6 && // target
					vallen == DHT_ADDRESS_SIZE &&
					path_initial[0] == 'a'
				)
				{	fields_parsed |= MSGFIELD_TARGET;
					target = (const DhtAddress*)val;
				}
				else
				if(	*((DWORD*)key) == 0x6f666e69 && *((DWORD*)(key+5)) == 0x68736168 && keylen == 9 && // info_hash
					vallen == DHT_ADDRESS_SIZE &&
					path_initial[0] == 'a'
				)
				{	fields_parsed |= MSGFIELD_INFOHASH;
					info_hash = (const DhtAddress*)val;
				}
				else
				if(	*((DWORD*)key) == 0x65646f6e && key[4] == 's' && keylen == 5  // nodes
					&& path_initial[0] == 'r'
				)
				{	if(vallen%sizeof(dht_compact_node)!=0)
						return false;
					nodes = (dht_compact_node*)val;
					nodes_size = vallen/sizeof(dht_compact_node);
					fields_parsed |= MSGFIELD_NODES;
				}
				else
				if(	*((DWORD*)key) == 0x65646f6e && key[4] == 's' && key[5] == '6' && keylen == 6  // nodes6
					&& path_initial[0] == 'r'
				)
				{	if(vallen%sizeof(dht_compact_node_v6)!=0)
						return false;
					nodes6 = (dht_compact_node_v6*)val;
					nodes6_size = vallen/sizeof(dht_compact_node_v6);
					fields_parsed |= MSGFIELD_NODES6;
				}
				else
				if( *((DWORD*)key) == 0x656b6f74 && key[4] == 'n' && keylen == 5 && // token
					(path_initial[0] == 'a' || path_initial[0] == 'r')
				)
				{	if(vallen>DHT_MESSAGE_TOKEN_MAXLEN)
						return false;
					token = val;
					token_length = vallen;
					fields_parsed |= MSGFIELD_TOKEN;
				}
				else
				if( *((DWORD*)key) == 0x626d7773 && keylen == 4 && // swmb (swarm member)
					(path_initial[0] == 'r' || path_initial[0] == 'a') && vallen == 1
				)
				{	swarm_member = (val[0] == '1' || val[0] == 1);
				}
			}
			// END
			//////////////////////////////////////////////////////////////////
		}
		else if(msg[0] == 'd') // parse dict
		{
			level++;
			path_initial[level-1] = key[0];
			path_initial[level] = 0;
			msg++;
			continue;
		}
		else if(msg[0] == 'l') // parse list, support string/int list only
		{
			msg++;
			int i = 0;

			if( *((DWORD*)key) == 0x756c6176 && *(WORD *)(key + 4) == 0x7365 && level == 1 && keylen == 6 && path_initial[0] == 'r') // values
			{
				peers_count = 0;
				fields_parsed |= MSGFIELD_PEERS;

				// collect nodes
				while(msg<end)
				{
					if(msg[0]>='0' && msg[0]<='9')
					{
						int vallen = 0;
						LPCSTR val;
						{	int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(vallen);
							if(	eta == 0 ||
								(vallen != 6 && vallen != 18) ||
								msg[eta] != ':'
							)
								return false;

							val = msg + eta + 1;
						}
						msg = val + vallen;

						if(peers_count < DHT_MESSAGE_PEERINFO_MAXCOUNT)
						{
							if(!bViaIpv4)
								peers[peers_count].IPv6() = *(dht_compact_host_v6*)val;
							else
								peers[peers_count].IPv4() = *(dht_compact_host*)val;

							peers_count++;
						}
					}
					else if(msg[0] == 'e'){ break; }
					else
					{	// dict/int shouldn't in the list
						return false;
					}
					i++;
				}
			}
			else if(*((DWORD*)key) == 0x76746c61 && (*(DWORD*)(key + 4) & 0xffffff) == 0x736c61 && level == 1 && keylen == 7 && path_initial[0] == 'r') // altvals
			{
				alt_peers_count = 0;
				fields_parsed |= MSGFIELD_ALTVALS;

				// collect nodes
				while(msg<end)
				{
					if(msg[0]>='0' && msg[0]<='9')
					{
						int vallen = 0;
						LPCSTR val;
						{	int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(vallen);
							if(	eta == 0 ||
								(vallen != 6 && vallen != 18) ||
								msg[eta] != ':'
							)
								return false;

							val = msg + eta + 1;
						}
						msg = val + vallen;

						if(alt_peers_count < DHT_MESSAGE_PEERINFO_MAXCOUNT)
						{
							if(bViaIpv4 && vallen == 18)
								alt_peers[alt_peers_count].IPv6() = *(dht_compact_host_v6*)val;
							else if(!bViaIpv4 && vallen == 6)
								alt_peers[alt_peers_count].IPv4() = *(dht_compact_host*)val;
							else
								return false;

							alt_peers_count++;
						}
					}
					else if(msg[0] == 'e'){ break; }
					else
					{	// dict/int shouldn't in the list
						return false;
					}
					i++;
				}
			}
			else
			{	// something unknown
				while(msg<end)
				{
					if(msg[0]>='0' && msg[0]<='9')
					{
						int vallen = 0;
						LPCSTR val;
						{	int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(vallen);
							if(eta == 0 || msg[eta] != ':')
								return false;
							val = msg + eta + 1;
						}
						msg = val + vallen;

						// get a string in a list
						//_LOGC('L'<<level<<'\t'<<path_initial<<'/'<<rt::String_Ref(key,keylen)<<'['<<i<<"]:"<<rt::String_Ref(val, vallen));
					}
					else if(msg[0] == 'i')
					{
						msg++;
						int val;
						int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(val);
						msg += eta + 1;
						if(msg[-1] != 'e')
							return false;

						// get a int in a list
						//_LOGC('L'<<level<<'\t'<<path_initial<<'/'<<rt::String_Ref(key,keylen)<<'['<<i<<"]:"<<val<<" (int)");
					}
					else if(msg[0] == 'e'){ break; }
					else
					{	// dict in list is not supported
						return false;
					}
					i++;
				}
			}

			if(msg[0] != 'e')
				return false;
			msg++;
		}
		else if(msg[0] == 'i')
		{
			msg++;
			int val;
			int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(val);
			msg += eta + 1;
			if(msg[-1] != 'e')
				return false;

			if(*((ULONGLONG*)key) == 0x5f6465696c706d69ULL && *((DWORD*)(key + 8)) == 0x74726f70UL && keylen == 12 && // implied_port
				path_initial[0] == 'a'
				)
			{
				if(val != 0 && val != 1)
					return false;
				implied_port = val != 0;
			}
			else if(*((DWORD*)key) == 0x74726f70 && keylen == 4 && // port
				path_initial[0] == 'a'
				)
			{
				fields_parsed |= MSGFIELD_ANNOUNCE_PORT;
				announced_port = val;
			}
			//_LOGC('L'<<level<<'\t'<<path_initial<<'/'<<rt::String_Ref(key,keylen)<<':'<<val<<" (int)");
		}
		else
			return false;
	}

	if((fields_parsed&MSGFIELD_ESSENCE) == MSGFIELD_ESSENCE)
	{
		if(y == 'r')
		{
			if(query_transId_length != 9)
				return false;
			//if(	*((WORD*)(query_transId+1)) != rd.trans_token[0] &&
			//	*((WORD*)(query_transId+1)) != rd.trans_token[1]
			//)return false;

			UINT q = query_transId[0];
			UINT tx = *((WORD*)(query_transId+3));

			reply_transId_tick = *((UINT*)(query_transId+5));
			reply_transId_verb = q&(RQTAG_MASK_VERB|RQTAG_MASK_PLUS);
			reply_transId_txtype = q&RQTAG_MASK_TXTYPE;
			reply_transId_tx = tx;
			
			fields_parsed |= MSGFIELD_TRANSID_REPLY;
		}
		else
		{
			fields_parsed &= ~(MSGFIELD_EXTERNAL_IPV4|MSGFIELD_EXTERNAL_IPV6);
		}

		return true;
	}

	if(implied_port)
	{	fields_parsed &= ~MSGFIELD_ANNOUNCE_PORT;
	}

	if(!swarm_member)
	{
		fields_parsed &= ~(MSGFIELD_CLOAK_IPV4|MSGFIELD_CLOAK_IPV6);
		cip_v4 = nullptr;
	}

	return false;
}

void DhtMessageCompose::_ChangeToken()
{
	_TransToken[1] = _TransToken[0];
	__RNG.Randomize(_TransToken[0]);
}

bool BencodeToString(LPCSTR msg, UINT len, LPSTR outbuf, UINT* outbuf_len)
{
	UINT bufsize = *outbuf_len;
	ASSERT(bufsize);

	UINT& outsize = *outbuf_len;
	outsize = 0;

	LPCSTR end = msg + len;

	char level_close_tag[2048];

	int level = -1;
	int keylen = 0;
	LPCSTR key = nullptr;

	if(msg[0] != 'd')return false;

	while(msg < end)
	{
		// parse a value
		if(msg[0] == 'd') // parse dict
		{
			level++;
			level_close_tag[level] = '}';
			msg++;
			outbuf[outsize++] = '{';	if(bufsize == outsize)return false;
			outbuf[outsize++] = ' ';	if(bufsize == outsize)return false;
			continue;
		}
		else
		if(msg[0] == 'e')	// level up
		{	if(level>=0)
			{	
				if(	outbuf[outsize-1] == ' ' &&
					outbuf[outsize-2] == ','
				)
				{	outsize -= 2;
				}

				outbuf[outsize++] = ' ';					if(bufsize == outsize)return false;
				outbuf[outsize++] = level_close_tag[level];	if(bufsize == outsize)return false;
				if(level)
				{	outbuf[outsize++] = ',';	if(bufsize == outsize)return false;
					outbuf[outsize++] = ' ';	if(bufsize == outsize)return false;
				}

				level--;
				msg++;
				continue;
			}
			else{ return false; }
		}
		else
		if(msg[0] == 'l')
		{	
			level++;
			level_close_tag[level] = ']';
			msg++;
			outbuf[outsize++] = '[';	if(bufsize == outsize)return false;
			outbuf[outsize++] = ' ';	if(bufsize == outsize)return false;
			continue;
		}

		if(level_close_tag[level] == '}')
		{
			// parse key
			{	int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(keylen);
				if(eta == 0 || keylen == 0 || msg[eta] != ':')return false;
				key = msg + eta + 1;
			}
			msg = key + keylen;

			if(outsize + keylen >= bufsize)return false;
			memcpy(&outbuf[outsize], key, keylen);	outsize += keylen;

			outbuf[outsize++] = ':';	if(bufsize == outsize)return false;
		}

		// parse value
		if(msg[0]>='0' && msg[0]<='9')
		{
			int vallen = 0;
			LPCSTR val;
			{	int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(vallen);
				if(eta == 0 || msg[eta] != ':')return false;
				val = msg + eta + 1;
			}
			msg = val + vallen;

			if(vallen)
			{
				if(level == 0 && keylen == 2 && key[0] == 'i' && key[1] == 'p' && vallen == 6)
				{
					IPv4 addr;
					addr.Set((LPCVOID)(val), ntohs(*((WORD const *)(val + 4))));
					tos str(addr);
					if(outsize + str.GetLength() >= bufsize)return false;
					outsize += (UINT)str.CopyTo(&outbuf[outsize]);
					val += 6;
					vallen -= 6;
				}
				else if(level == 1 && keylen == 5 && *(DWORD *)key == 0x65646f6e && key[4] == 's' && vallen > 0 && vallen % 26 == 0) // nodes
				{
					outbuf[outsize++] = '<';	if(bufsize == outsize)return false;
					while(vallen > 0) {
						rt::tos::Binary<42, false> cstr(val, 20);
						if(outsize + cstr.GetLength() >= bufsize)return false;
						outsize += (UINT)cstr.CopyTo(&outbuf[outsize]);
						outbuf[outsize++] = '@';	if(bufsize == outsize)return false;
						IPv4 addr;
						addr.Set((LPCVOID)(val + 20), ntohs(*((WORD const *)(val + 24))));
						tos str(addr);
						if(outsize + str.GetLength() >= bufsize)return false;
						outsize += (UINT)str.CopyTo(&outbuf[outsize]);
						outbuf[outsize++] = ' ';	if(bufsize == outsize)return false;
						outbuf[outsize++] = '|';	if(bufsize == outsize)return false;
						outbuf[outsize++] = ' ';	if(bufsize == outsize)return false;
						val += 26;
						vallen -= 26;
					}
					outsize -= 2;
					outbuf[outsize++] = '>';	if(bufsize == outsize)return false;
				}
				else if(level == 2 && keylen == 6 && *(DWORD *)key == 0x756c6176 && *(WORD *)(key + 4) == 0x7365 && vallen == 6) // values
				{
					outbuf[outsize++] = '<';	if(bufsize == outsize)return false;
					IPv4 addr;
					addr.Set((LPCVOID)val, ntohs(*((WORD const *)(val + 4))));
					tos str(addr);
					if(outsize + str.GetLength() >= bufsize)return false;
					outsize += (UINT)str.CopyTo(&outbuf[outsize]);
					outbuf[outsize++] = '>';	if(bufsize == outsize)return false;
				}
				else if(rt::String_Ref(val, vallen).HasNonPrintableAscii())
				{	
					if(vallen < 512)
					{	rt::tos::Binary<512*2> cstr(val, vallen);
						outbuf[outsize++] = '<';	if(bufsize == outsize)return false;

						if(outsize + cstr.GetLength() >= bufsize)return false;
						outsize += (UINT)cstr.CopyTo(&outbuf[outsize]);
						outbuf[outsize++] = '>';	if(bufsize == outsize)return false;
					}
					else
					{	if(outsize + 11 + 15 >= bufsize)return false;
						outsize += (UINT)(rt::SS("(Too Long) ") + rt::tos::FileSize<true,true>(vallen)).CopyTo(&outbuf[outsize]);
					}
				}
				else
				{
					outbuf[outsize++] = '"';	if(bufsize == outsize)return false;
					if(outsize + vallen >= bufsize)return false;
					memcpy(&outbuf[outsize], val, vallen);
					outsize += vallen;
					outbuf[outsize++] = '"';	if(bufsize == outsize)return false;
				}
			}
			else
			{	outbuf[outsize++] = 'n';	if(bufsize == outsize)return false;
				outbuf[outsize++] = 'u';	if(bufsize == outsize)return false;
				outbuf[outsize++] = 'l';	if(bufsize == outsize)return false;
				outbuf[outsize++] = 'l';	if(bufsize == outsize)return false;
			}
			outbuf[outsize++] = ',';	if(bufsize == outsize)return false;
			outbuf[outsize++] = ' ';	if(bufsize == outsize)return false;
		}
		else if(msg[0] == 'i')
		{
			msg++;
			int val;
			int eta = rt::String_Ref(msg, end).ToNumber<int,10,false,0,0>(val);
			msg += eta + 1;
			if(msg[-1] != 'e')return false;

			if(outsize + 15 >= bufsize)return false;
			outsize += (UINT)rt::tos::Number(val).CopyTo(&outbuf[outsize]);
			outbuf[outsize++] = ',';	if(bufsize == outsize)return false;
			outbuf[outsize++] = ' ';	if(bufsize == outsize)return false;
		}
		else if(msg[0] == 'd' || msg[0] == 'l')
		{
			continue;
		}
		else return false;
	}

	return true;
}

DhtMessageCompose::DhtMessageCompose()
	:__RNG((UINT)time(nullptr))
{
}

#define QUERY_COMPOSE_COMMON(tx)	 \
		    rt::DS(_TransToken, 2) +  /* WORD Transaction id for better security (reply message should be received from nodes we contacted*/ \
            rt::DS(&tx, 2) + \
            rt::DS(&_Tick, 4) + /* UINT send _Tick, for estimating round trip latency */ \
            rt::SS("1:v4:") + rt::DS(&_DhtVer, 4) + \
            rt::SS("3:app4:") + rt::DS(&_AppTag, 4) \

#define REPLY_COMPOSE_COMMON	\
			rt::SS("1:t") + transid_len + ':' + rt::String_Ref(transid, transid_len) + \
            rt::SS("1:v4:") + rt::DS(&_DhtVer, 4) + \
            rt::SS("3:app4:") + rt::DS(&_AppTag, 4) \

UINT DhtMessageCompose::ComposeQueryPing(LPSTR buf, UINT bufsize, DWORD rqtag, int tx)
{	
	ASSERT(tx>=0 && tx<=0xffff);
	UINT len = (UINT)
	(	rt::SS("d1:ad2:id") + 
		DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
		rt::SS("e1:q4:ping1:t9:") + ((char)(rqtag|RQTAG_VERB_PING)) + 
		QUERY_COMPOSE_COMMON(tx) +
		rt::SS("1:y1:qe")
	).CopyTo(buf);
	ASSERT(len <= bufsize);	return len;
}

UINT DhtMessageCompose::ComposeQueryPing(LPSTR buf, UINT bufsize, const IPv6& this_na, DWORD rqtag, int tx)
{
	ASSERT(tx >= 0 && tx <= 0xffff);
    
	//char ipv6_part[32];
	//UINT ipv6_len = 0;
 //   if(!this_na.IsEmpty())
 //       (rt::SS("3:ip6") + rt::SS("18:") + rt::String_Ref((const char*)&this_na, 18)).CopyTo(ipv6_part);

    UINT len = (UINT)
        (rt::SS("d1:ad2:id") +
            DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
            rt::SS("e1:q4:ping1:t9:") + ((char)(rqtag | RQTAG_VERB_PING)) +
			QUERY_COMPOSE_COMMON(tx) +
            //rt::DS(ipv6_part, ipv6_len) +
            rt::SS("1:y1:qe")
            ).CopyTo(buf);
    
	ASSERT(len <= bufsize);	return len;
}

UINT DhtMessageCompose::ComposeQueryFindNode(LPSTR buf, UINT bufsize, const DhtAddress& target, DWORD rqtag, int tx)
{	
	ASSERT(tx>=0 && tx<=0xffff);
	UINT len = (UINT)
	(	rt::SS("d") +
			rt::SS("1:a") +	rt::SS("d") +
				rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
				rt::SS("6:target") + DHT_ADDRESS_SIZE + ':' + rt::DS(target.addr, DHT_ADDRESS_SIZE) +
			rt::SS("e") + 
			rt::SS("1:q") + rt::SS("9:find_node") +
			rt::SS("1:t") + rt::SS("9:") + ((char)(rqtag|RQTAG_VERB_FINDNODE)) + 
			QUERY_COMPOSE_COMMON(tx) +
			rt::SS("1:y") + rt::SS("1:q") +
			//rt::SS("4:want") + rt::SS("l") +
			//	rt::SS("2:n4") +	// ask for ipv4
			//	rt::SS("2:n6") +	// ask for ipv6
			//rt::SS("e") +
		rt::SS("e")
	).CopyTo(buf);

	ASSERT(len <= bufsize);
	return len;
}

UINT DhtMessageCompose::ComposeQueryGetPeer(LPSTR buf, UINT bufsize, const DhtAddress& target, DWORD rqtag, int tx, bool swmb)
{
	ASSERT(tx>=0 && tx<=0xffff);
	UINT len = (UINT)
	(	rt::SS("d") +
			rt::SS("1:a") + rt::SS("d") +
				rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
				rt::SS("9:info_hash") + DHT_ADDRESS_SIZE + ':' + rt::DS(target.addr, DHT_ADDRESS_SIZE)
	).CopyTo(buf);

	if(swmb)
	{
		len += (UINT)
				(rt::SS("4:swmb") + rt::SS("1:1")).CopyTo(buf + len);
	}

	len +=	(UINT)
	(
			rt::SS("e") +
			rt::SS("1:q") + rt::SS("9:get_peers") + 
			rt::SS("1:t") + rt::SS("9:") + ((char)(rqtag|RQTAG_VERB_GETPEERS)) + 
			QUERY_COMPOSE_COMMON(tx) +
			rt::SS("1:y") + rt::SS("1:q") +
		rt::SS("e")
	).CopyTo(buf + len);

	ASSERT(len <= bufsize);
	return len;
}

UINT DhtMessageCompose::ComposeQueryGetPeer(LPSTR buf, UINT bufsize, const DhtAddress& target, const NetworkNodeDesc& nd, const NetworkAddress& altip, DWORD rqtag, int tx, bool swmb)
{
	ASSERT(sizeof(NetworkNodeDesc) == 12);
	ASSERT(tx>=0 && tx<=0xffff);
	UINT len = (UINT)
	(	rt::SS("d") +
			rt::SS("1:a") + rt::SS("d") +
				rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
				rt::SS("9:info_hash") + DHT_ADDRESS_SIZE + ':' + rt::DS(target.addr, DHT_ADDRESS_SIZE)
	).CopyTo(buf);

	if(swmb)
		len += (UINT)(rt::SS("4:swmb") + rt::SS("1:1")).CopyTo(buf + len);

	len +=	(UINT)
	(	rt::SS("e") +
		rt::SS("1:q") + rt::SS("9:get_peers") +
		rt::SS("1:t") + rt::SS("9:") + ((char)(rqtag|RQTAG_VERB_GETPEERS)) + 
		QUERY_COMPOSE_COMMON(tx) +
		rt::SS("2:nd") + rt::SS("12:") + rt::String_Ref((LPCSTR)&nd, 12) 
	).CopyTo(buf + len);

	if(altip.IsIPv4())
		len += (UINT)(rt::SS("5:altip") + sizeof(IPv4) + ':' + rt::DS(altip.IPv4())).CopyTo(buf + len);
	else if(altip.IsIPv6())
		len += (UINT)(rt::SS("5:altip") + sizeof(IPv6) + ':' + rt::DS(altip.IPv6())).CopyTo(buf + len);
		
	len +=	(UINT)
	(	rt::SS("1:y") + rt::SS("1:q") +
		rt::SS("e")
	).CopyTo(buf + len);

	ASSERT(len <= bufsize);
	return len;
}


UINT DhtMessageCompose::ComposeQueryAnnouncePeer(LPSTR buf, UINT bufsize, const DhtAddress& target, WORD port, const NetworkNodeDesc& nd, LPCVOID token, UINT token_size, DWORD rqtag, int tx)
{
	ASSERT(sizeof(NetworkNodeDesc) == 12);
	ASSERT(tx>=0 && tx<=0xffff);
	UINT len = (UINT)
	(	rt::SS("d") +
			rt::SS("1:a") + rt::SS("d") +
				rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
				rt::SS("9:info_hash") + DHT_ADDRESS_SIZE + ':' + rt::DS(target.addr, DHT_ADDRESS_SIZE) +
				rt::SS("5:token") + token_size + ':' + rt::DS(token, token_size) + 
				rt::SS("4:port") + rt::SS("i") + port + 'e' +
				rt::SS("12:implied_port") + rt::SS("i1e") +
			rt::SS("e") +
			rt::SS("1:q") + rt::SS("13:announce_peer") +
			rt::SS("1:t") + rt::SS("9:") + ((char)(rqtag|RQTAG_VERB_ANNOUNCEPEER)) +
			QUERY_COMPOSE_COMMON(tx) +
			rt::SS("2:nd") + rt::SS("12:") + rt::DS(&nd, 12) +
			rt::SS("1:y") + rt::SS("1:q") +
		rt::SS("e")
	).CopyTo(buf);

	ASSERT(len <= bufsize);
	return len;
}

UINT DhtMessageCompose::ComposeReplyPing(LPSTR buf, UINT bufsize, LPCSTR transid, UINT transid_len, const NetworkAddress& to)
{	
	UINT len = (UINT)
	(	
		rt::SS("d") +
			rt::SS("2:ip") + to.AddressLength() + ':' + rt::DS(to.Address(), to.AddressLength()) +
			rt::SS("1:r") + rt::SS("d") +
				rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
			rt::SS("e") +
			REPLY_COMPOSE_COMMON +
			rt::SS("1:y") + rt::SS("1:r") +
		rt::SS("e")
	).CopyTo(buf);

	ASSERT(len <= bufsize);
	return len;
}

UINT DhtMessageCompose::ComposeReplyPing(LPSTR buf, UINT bufsize, LPCSTR transid, UINT transid_len, const IPv6& this_na, const NetworkAddress& to)
{
	//char ipv6_part[32];
	//UINT ipv6_len = 0;
 //   if(!this_na.IsEmpty())
 //       (rt::SS("3:ip6") + rt::SS("18:") + rt::String_Ref((const char*)&this_na, 18)).CopyTo(ipv6_part);
    
	UINT len = (UINT)
	(	
		rt::SS("d") +
			rt::SS("2:ip") + to.AddressLength() + ':' + rt::DS(to.Address(), to.AddressLength()) +
			rt::SS("1:r") + rt::SS("d") +
				rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE) +
			rt::SS("e") +
			REPLY_COMPOSE_COMMON +
			//rt::DS(ipv6_part, ipv6_len) +
			rt::SS("1:y") + rt::SS("1:r") +
		rt::SS("e")
	).CopyTo(buf);

	ASSERT(len <= bufsize);
	return len;
}

UINT DhtMessageCompose::ComposeReplyFindNode(LPSTR buf, UINT bufsize, LPCSTR transid, UINT transid_len, const DhtSpace* dht, const DhtAddress& target, const NetworkAddress& to)
{	
    ASSERT(to.Type() == NADDRT_IPV4 || to.Type() == NADDRT_IPV6);
	DhtSpace::_CollectedNode n[DHT_TRANSCATION_FINDNODE_CANDIDATE_SIZE];
	UINT co = dht->GetClosestNodes(target, _Tick, n, sizeofArray(n));
	
	UINT len = 0;
	len +=	(UINT)
			(	rt::SS("d") +
					rt::SS("2:ip") + to.AddressLength() + ':' + rt::DS(to.Address(), to.AddressLength()) +
					rt::SS("1:r") + rt::SS("d") +
						rt::SS("2:id") + DHT_ADDRESS_SIZE + ':' + rt::DS(_NodeId.addr, DHT_ADDRESS_SIZE)
			).CopyTo(buf + len);

	if(to.Type() == NADDRT_IPV4)
	{
		len += (UINT)(rt::SS("5:nodes") + (UINT)(sizeof(DhtMessageParse::dht_compact_node)*co) + ':').CopyTo(buf + len);
		auto* final_nodes = (DhtMessageParse::dht_compact_node*)&buf[len];
		for(UINT i=0; i<co; i++)
		{	
			final_nodes[i].DhtAddress = n[i].node.DhtAddress;
			final_nodes[i].NetAddress = n[i].node.NetAddress.IPv4();
		}
		len += sizeof(DhtMessageParse::dht_compact_node)*co;
	}
	else if(to.Type() == NADDRT_IPV6)
	{
		len += (UINT)(rt::SS("6:nodes6") + (UINT)(sizeof(DhtMessageParse::dht_compact_node_v6)*co) + ':').CopyTo(buf + len);
		auto* final_nodes = (DhtMessageParse::dht_compact_node_v6*)&buf[len];
		for(UINT i=0; i<co; i++)
		{	
			final_nodes[i].DhtAddress = n[i].node.DhtAddress;
			final_nodes[i].NetAddress = n[i].node.NetAddress.IPv6();
		}
		len += sizeof(DhtMessageParse::dht_compact_node_v6)*co;
	}
	
	len +=	(UINT)
			(		rt::SS("e") +
					REPLY_COMPOSE_COMMON +
					rt::SS("1:y") + rt::SS("1:r") +
				rt::SS("e")
			).CopyTo(buf + len);

	ASSERT(len <= bufsize);
	return len;
}

#undef QUERY_COMPOSE_COMMON
#undef REPLY_COMPOSE_COMMON

} // namespace upw
