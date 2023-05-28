#include "../secure_identity.h"
#include "../netsvc_core.h"
#include "../local_swarm.h"
#include "../api/local_api.h"
#include "mlt_packet.h"
#include "mlt.h"

//#define PLATFORM_DEBUG_BUILD

namespace upw
{

MultiLinkTunnels::MultiLinkTunnels(NetworkServiceCore* p)
	:_pCore(p)
{
	_pCore->SetPacketOnRecvCallBack(NET_PACKET_HEADBYTE_MLT, this, &MultiLinkTunnels::_OnRecv);
	_pCore->SetOnTickCallback(this, &MultiLinkTunnels::_OnTick);

	if(_pCore->HasAPI())
		_pCore->API().SetCommandExtension("mlt", this, &MultiLinkTunnels::_OnExecuteCommand);

	rt::Zero(_AppCallbacks);
}

MultiLinkTunnels::~MultiLinkTunnels()
{
}

std::shared_ptr<MLT_Tunnel> MultiLinkTunnels::_CreateTunnel(const MLT_TunnelCreateInfo& init, const rt::String_Ref& connectionData)
{
	std::unique_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
	{
		auto itor = _TunnelUniqueIDMap.find(init.PerDeviceUniqueId);
		if(itor != _TunnelUniqueIDMap.end())
		{
			auto itor2 = itor->second.find(init.DestinationDeviceAddr);
			if(itor2 != itor->second.end())
			{
				uint32_t id = itor2->second;
				auto itor3 = _TunnelIdMap.find(id);
				if(itor3 != _TunnelIdMap.end())
					return itor3->second;
			}
		}
	}

	// create the tunnel
	std::shared_ptr<MLT_Tunnel> pTunnel = std::make_shared<MLT_Tunnel>(_pCore, init, _NextTunnelId, connectionData);
	if(pTunnel == nullptr)
		return nullptr;

	_TunnelIdMap.emplace(_NextTunnelId, pTunnel);
	_TunnelUniqueIDMap.emplace(init.PerDeviceUniqueId, std::map<DhtAddress, uint32_t>());
	_TunnelUniqueIDMap[init.PerDeviceUniqueId].emplace(init.DestinationDeviceAddr, _NextTunnelId);
	int ret = _NextTunnelId;
	_NextTunnelId++;

	lock.unlock();
	init.EventHandler->OnAttach(MLT_TUNNEL_HANDLE(pTunnel->GetTunnelId()));

	return pTunnel;
}

MLT_TUNNEL_HANDLE MultiLinkTunnels::OpenTunnel(const MLT_TunnelCreateInfo& init, const NodeAccessPoints& aps, const rt::String_Ref& connection_data)
{
	std::shared_ptr<MLT_Tunnel> pTunnel;

	// If there's already a tunnel with the same unique id. return it. (ignore difference in TunnelCreateInfo)
	{
		std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);

		auto itor = _TunnelUniqueIDMap.find(init.PerDeviceUniqueId);
		if(itor != _TunnelUniqueIDMap.end())
		{
			auto itor2 = itor->second.find(init.DestinationDeviceAddr);
			if(itor2 != itor->second.end())
			{
				uint32_t id = itor2->second;
				auto itor3 = _TunnelIdMap.find(id);
				if(itor3 != _TunnelIdMap.end())
					pTunnel = itor3->second;
			}
		}
	}

	// create the tunnel
	if(!pTunnel)
		pTunnel = _CreateTunnel(init, connection_data);
	else
		pTunnel->Awaken();
	if(!pTunnel)
		return MLT_TUNNEL_HANDLE::MLT_TUNNEL_INVALID_HANDLE;

	pTunnel->CreateLinksFromAPs(aps);

	return pTunnel->GetHandle();
}

void MultiLinkTunnels::CloseTunnel(MLT_TUNNEL_HANDLE handle)
{
	std::unique_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);			// using unique_lock here
	auto itor = _TunnelIdMap.find(uint32_t(handle));
	if(itor != _TunnelIdMap.end())
	{
		std::shared_ptr<MLT_Tunnel> pTunnel = itor->second;
		_TunnelIdMap.erase(itor);
		if(pTunnel)
		{
			auto itor2 = _TunnelUniqueIDMap.find(pTunnel->GetTunnelUID());
			if(itor2 != _TunnelUniqueIDMap.end())
			{
				itor2->second.erase(pTunnel->GetDestinationDHTAddress());
				if(itor2->second.size() == 0)
					_TunnelUniqueIDMap.erase(itor2);
			}

			lock.unlock();

			pTunnel->Close(false, true);

			return;
		}
	}
}

void MultiLinkTunnels::CloseTunnel(const MLT_TunnelPDUID &uid, const DhtAddress &destDHTAddr)
{
	std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);			// using shared_lock here since actual closing in done in the CloseTunnel call at the end
	auto itor = _TunnelUniqueIDMap.find(uid);
	if(itor != _TunnelUniqueIDMap.end())
	{
		auto itor2 = itor->second.find(destDHTAddr);
		if(itor2 != itor->second.end())
		{
			MLT_TUNNEL_HANDLE handle = MLT_TUNNEL_HANDLE(itor2->second);
			lock.unlock();
			CloseTunnel(handle);

			return;
		}
	}
}

void MultiLinkTunnels::CloseTunnels(const MLT_TunnelPDUID &uid)
{
	std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);			// using shared_lock here since actual closing in done in the CloseTunnel call at the end
	std::vector<uint32_t> toCloseTunnelHandles;
	auto itor = _TunnelUniqueIDMap.find(uid);
	if(itor != _TunnelUniqueIDMap.end())
	{
		toCloseTunnelHandles.reserve(itor->second.size());
		for(auto itor2 : itor->second)
		{
			toCloseTunnelHandles.push_back(itor2.second);
		}
	}
	lock.unlock();
	for(uint32_t handle : toCloseTunnelHandles)
		CloseTunnel(MLT_TUNNEL_HANDLE(handle));
}


void MultiLinkTunnels::_OnTick(uint32_t tick_in_100ms, int64_t net_ts_in_ms)
{
	std::vector<std::shared_ptr<MLT_Tunnel>> tunnels;

	// first make a copy of all tunnel pointers so that the lock is released when calling OnTick() on each tunnel
	{
		std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
		tunnels.reserve(_TunnelIdMap.size());
		for(auto &itor : _TunnelIdMap)
		{
			tunnels.push_back(itor.second);
		}
	}

	for(auto &itor : tunnels)
	{
		itor->OnTick(tick_in_100ms, net_ts_in_ms);
	}

	// check once per second
	if(tick_in_100ms % 10 == 0)
	{
		bool bBusy = false;
		for(auto& itor : tunnels)
		{
			if(itor->IsBusy())
			{
				bBusy = true;
				break;
			}
		}
		if(bBusy != _bBusy)
		{
			_bBusy = bBusy;
			if(_bBusy)
				CoreEvent(MODULE_NETWORK, NETWORK_MULTILINK_BUSY);
			else
				CoreEvent(MODULE_NETWORK, NETWORK_MULTILINK_IDLE);
		}
	}
}

#if defined(PLATFORM_DEBUG_BUILD)

class DebugOutgoingFileReader : public MLT_OutgoingFileReader
{
	std::string _fn;
public:
	DebugOutgoingFileReader(const std::string &fn)
		:_fn(fn)
	{
		_LOG("DebugOutgoingFileReader constructor " << _fn.c_str());
	}

	~DebugOutgoingFileReader()
	{
		_LOG("DebugIncomingFileWriter destructor " << _fn.c_str());
	}

	virtual uint32_t Read(uint64_t offset, uint32_t readLen, uint8_t *pBuffer) override
	{
		os::Randomize(pBuffer, readLen);
		FILE *_fp = fopen(_fn.c_str(), "wb");
		if(_fp)
		{
			fseek(_fp, offset, SEEK_SET);
			fwrite(pBuffer, 1, readLen, _fp);
			fclose(_fp);
		}
		return readLen;
	}
};

struct DebugEvents : public MLT_TunnelEventHandler
{
	virtual void OnMessageSent(void *pMsgCookie, bool bSuccessfullyDelivered) override
	{
		delete pMsgCookie;
	}

	virtual void OnMessageReceived(const uint8_t *pData, uint32_t dataLen) override
	{
		auto& a = GetHasher();
		a.Update(pData, dataLen);
		HashValue h;
		a.Finalize(&h);
		_LOG("[MLT] debug tunnel " << _uniqueId << " received data with SHA256: " << rt::tos::Base32CrockfordLowercaseOnStack<>(h));
	}

	virtual void OnConnected(MLT_TUNNEL_HANDLE h) override
	{
		_LOG("[MLT] debug tunnel " << _uniqueId << " connected");
	}

	virtual void OnDisconnected(MLT_TUNNEL_HANDLE h, bool bClosedByDestination) override
	{
		if(bClosedByDestination)
		{
			_LOG("[MLT] debug tunnel " << _uniqueId << " got closed from other side");
			_pCore->CloseTunnel(_uniqueId, _destAddr);
		}
		else
		{
			_LOG("[MLT] debug tunnel " << _uniqueId << " disconnected");
		}
	}

	virtual MLT_OutgoingFileReader* OnFileRequest(MLT_TUNNEL_HANDLE h, const MLT_FileHash &fileHash, uint64_t fileSize) override
	{
		static uint32_t i = 0;
		return new DebugOutgoingFileReader("o_" + std::to_string(i++));
	}

	virtual void OnFileUnrequest(MLT_TUNNEL_HANDLE h, MLT_OutgoingFileReader* reader) override
	{
		delete reader;
	}

	virtual void OnFileDownloaded(MLT_TUNNEL_HANDLE h, const MLT_FileHash &hash) override
	{
		// TODO: implement
	}

	virtual void OnFileDownloadInterrupted(MLT_TUNNEL_HANDLE h, const MLT_FileHash &hash, FDI_Reason reason) override
	{
		// TODO: implement
	}

	virtual void OnLinkConnected(MLT_TUNNEL_HANDLE h, const NetworkAddress &senderAddr, const NetworkAddress *pBouncerAddr) override
	{
	}

	virtual void OnLinkDisconnected(MLT_TUNNEL_HANDLE h, const NetworkAddress &senderAddr, const NetworkAddress *pBouncerAddr) override
	{
	}

	DebugEvents(MultiLinkTunnels *pCore)
		: _pCore(pCore)
	{
	}

	MLT_TunnelPDUID _uniqueId;
	DhtAddress _destAddr;
	uint32_t handle;
	MultiLinkTunnels *_pCore;
};

class DebugIncomingFileWriter : public MLT_IncomingFileWriter
{
	std::string _fn;
	std::vector<uint8_t> _controlDataBuf;
public:
	DebugIncomingFileWriter(const std::string &fn)
		:_fn(fn)
	{
		_LOG("DebugIncomingFileWriter constructor " << _fn.c_str());
	}

	~DebugIncomingFileWriter()
	{
		_LOG("DebugIncomingFileWriter destructor " << _fn.c_str());
	}

	virtual bool SetControlData(const uint8_t *controlData, uint32_t controlDataLen) override
	{
		if(controlData == nullptr || controlDataLen == 0)
			return true;
		FILE *fp;
		fp = fopen((_fn + ".cb").c_str(), "wb");
		fwrite(controlData, 1, controlDataLen, fp);
		fclose(fp);

		return true;
	}

	virtual bool GetControlData(const uint8_t **data_out, uint32_t *outControlDataLen) override
	{
		FILE *fp;
		fp = fopen((_fn + ".cb").c_str(), "rb");
		if(fp != nullptr)
		{
			fseek(fp, 0, SEEK_END);
			_controlDataBuf.resize(ftell(fp));
			if(_controlDataBuf.size() != 0)
			{
				fseek(fp, 0, SEEK_SET);
				fread(&_controlDataBuf[0], 1, _controlDataBuf.size(), fp);
				fclose(fp);
			}
		}
		else
			_controlDataBuf.clear();

		if(data_out)
			*data_out = _controlDataBuf.size() > 0 ? &_controlDataBuf[0] : nullptr;
		if(outControlDataLen)
			*outControlDataLen = uint32_t(_controlDataBuf.size());

		return true;
	}
	virtual void FinalizeWrite() override
	{
		remove((_fn + ".cb").c_str());
	}
	virtual bool Write(uint64_t offset, uint8_t *data, uint32_t dataLen) override
	{
		bool ret = false;
		FILE *_fp = fopen(_fn.c_str(), "wb");
		if(_fp)
		{
			fseek(_fp, offset, SEEK_SET);
			if(fwrite(data, 1, dataLen, _fp) == dataLen)
				ret = true;
			fclose(_fp);
		}

		return ret;
	}
	virtual void Release() override
	{
		delete this;
	}
};

#endif

void MultiLinkTunnels::SetIncomingConnectionCallback(uint8_t app, MLT_AppCallback *call_back)
{
	if(call_back)
		_AppCallbacks[app] = call_back;
	else
		_AppCallbacks[app] = nullptr;
} // not thread-safe


bool MultiLinkTunnels::_ResolveIncomingConnection(void* connection_data, uint32_t connection_data_len, uint8_t app_id, MLT_TunnelCreateInfo* out_create_info)
{
#if defined(PLATFORM_DEBUG_BUILD)
	if(connection_data_len >= sizeof(uint32_t) && *(uint32_t*)connection_data == 0xdeadbeaf
		&& connection_data_len == sizeof(uint32_t) + sizeof(uint8_t) + MLT_TunnelPDUID::LEN + DHT_ADDRESS_SIZE + sizeof(MLT_TunnelCipherSecret))
	{
		out_create_info->App = *(uint8_t*)(((uint8_t*)connection_data) + sizeof(uint32_t));
		out_create_info->PerDeviceUniqueId = *(MLT_TunnelPDUID*)(((char*)connection_data) + sizeof(uint32_t) + sizeof(uint8_t));
		out_create_info->DestinationDeviceAddr = *(DhtAddress*)(((char*)connection_data) + sizeof(uint32_t) + sizeof(uint8_t) + MLT_TunnelPDUID::LEN);
		out_create_info->Secret = *(MLT_TunnelCipherSecret*)(((uint8_t*)connection_data) + sizeof(uint32_t) + sizeof(uint8_t) + MLT_TunnelPDUID::LEN + DHT_ADDRESS_SIZE);
		DebugEvents *handler = new DebugEvents(this);
		handler->_uniqueId = out_create_info->PerDeviceUniqueId;
		handler->_destAddr = out_create_info->DestinationDeviceAddr;
		out_create_info->EventHandler = handler;

		return true;
	}
#endif

	if(!_AppCallbacks[app_id])
		return false;

	return _AppCallbacks[app_id]->ResolveIncomingConnection(connection_data, connection_data_len, out_create_info);
}

bool MultiLinkTunnels::_IdentifyIncomingConnection(void* connection_data, uint32_t connection_data_len, uint8_t app_id, MLT_TunnelPDUID* id_out, DhtAddress *dest_addr_out)
{
#if defined(PLATFORM_DEBUG_BUILD)
	if(connection_data_len >= sizeof(uint32_t) && *(uint32_t*)connection_data == 0xdeadbeaf
		&& connection_data_len == sizeof(uint32_t) + sizeof(uint8_t) + MLT_TunnelPDUID::LEN + DHT_ADDRESS_SIZE + sizeof(MLT_TunnelCipherSecret))
	{
		if(id_out)
			*id_out = *(MLT_TunnelPDUID*)(((char*)connection_data) + sizeof(uint32_t) + sizeof(uint8_t));
		if(dest_addr_out)
			*dest_addr_out = *(DhtAddress*)(((char*)connection_data) + sizeof(uint32_t) + sizeof(uint8_t) + MLT_TunnelPDUID::LEN);
		return true;
	}

#endif

	if(!_AppCallbacks[app_id])
		return false;

	return _AppCallbacks[app_id]->IdentifyIncomingConnection(connection_data, connection_data_len, id_out, dest_addr_out);
}

void MultiLinkTunnels::_OnRecv(const void *pData, uint32_t len, const PacketRecvContext& ctx)
{
	MLT_IncomingPacketParser parser((uint8_t *)pData, len);
	if(!parser.IsHeaderValid())
		return;

	uint32_t tunnelId = 0xffffffff;
	if(parser.HasConnectionData())
	{
		MLT_TunnelPDUID uniqueId;
		DhtAddress destDHTAddr;
		bool bAccept = _IdentifyIncomingConnection((void*)parser.GetConnectionData(), (uint32_t)parser.GetConnectionDataLen(), parser.GetAppId(), &uniqueId, &destDHTAddr);
		if(bAccept)
		{
			{
				std::unique_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);

				// If there's already a tunnel with the same unique id, use it
				auto itor = _TunnelUniqueIDMap.find(uniqueId);
				if(itor != _TunnelUniqueIDMap.end())
				{
					auto itor2 = itor->second.find(destDHTAddr);
					if(itor2 != itor->second.end())
						tunnelId = itor2->second;
				}
			}

			if(tunnelId == 0xffffffff)
			{
				MLT_TunnelCreateInfo createInfo;
				createInfo.PerDeviceUniqueId = uniqueId;
				createInfo.DestinationDeviceAddr = destDHTAddr;
				createInfo.App = parser.GetAppId();
				bAccept = _ResolveIncomingConnection((void*)parser.GetConnectionData(), (uint32_t)parser.GetConnectionDataLen(), parser.GetAppId(), &createInfo);
				if(!bAccept)
					return;

				std::shared_ptr<MLT_Tunnel> pTunnel = _CreateTunnel(createInfo, rt::String_Ref((const char*)parser.GetConnectionData(), parser.GetConnectionDataLen()));
				if(pTunnel == nullptr)
					return;

				_LOG_WARNING("[MLT] New Tunnel " << pTunnel->GetTunnelId() << " from incoming connection data");

				//if(_AppCallbacks[createInfo.App])
				//	_AppCallbacks[createInfo.App]->OnEstablishIncomingConnection(&createInfo, MLT_TUNNEL_HANDLE(pTunnel->GetTunnelId()));

				tunnelId = pTunnel->GetTunnelId();
			}
		}
		else
		{
			tunnelId = parser.GetTunnelId();
			if(tunnelId == 0xffffffffu)
			{
				_LOG_WARNING("[MLT] Incoming packet connection data cannot be identified and has tunnelId of -1");
				return;
			}
		}
	}
	else
	{
		tunnelId = parser.GetTunnelId();
		if(tunnelId == 0xffffffffu)
		{
			_LOG_WARNING("[MLT] Incoming packet without connection data and has tunnelId of -1");
			return;
		}
	}

	std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
	auto itor = _TunnelIdMap.find(tunnelId);
	if(itor == _TunnelIdMap.end())
		return;
	std::shared_ptr<MLT_Tunnel> pTunnel = itor->second;
	if(!parser.VerifyCrcWithTunnelUID(pTunnel->GetTunnelUID()))
		return;

	lock.unlock();
	pTunnel->OnRecv(parser, ctx.RecvFrom, ctx.pRelayPeer);

	return;
}

bool TextToNetworkAddress(NetworkAddress &outAddr, rt::String_Ref line)
{
	if(line.GetLength() <= 6) return false;
	SSIZE_T port_pos = line.FindCharacterReverse(':');
	if(port_pos < 4)return false;

	int port;
	line.SubStr(port_pos + 1).ToNumber(port);
	if(port <= 0 || port > 0xffff)return false;

	if(line[0] == '[') // ipv6
	{
		if(line[port_pos - 1] != ']')return false;
		inet::InetAddrV6 addr;
		if(inet_pton(AF_INET6, ALLOCA_C_STRING(rt::String_Ref(line.Begin() + 1, &line[port_pos - 1])), &addr.sin6_addr))
		{
			addr.SetPort(port);
			if(addr.IsValidDestination())
				outAddr.IPv6().Set(addr);
		}
		else return false;
	}
	else
	{
		inet::InetAddr addr;
		if(inet_pton(AF_INET, ALLOCA_C_STRING(rt::String_Ref(line.Begin(), &line[port_pos])), &addr.sin_addr))
		{
			addr.SetPort(port);
			if(addr.IsValidDestination())
				outAddr.IPv4().Set(addr);
		}
		else return false;
	}

	return true;
}


bool MultiLinkTunnels::_OnExecuteCommand(const os::CommandLine& cmd, rt::String& out)
{
	rt::String_Ref op[10];
	rt::String_Ref(cmd.GetText(0)).Split(op, sizeofArray(op), '.');

	if(op[1] == "help")
	{
		_LOG(".stat [tunnel id]");
		_LOG(".msg tunnel_id msg_length");
		_LOG(".file tunnel_id file_length");
		_LOG(".close tunnel_id");
		_LOG(".dump tunndel_id");
		_LOG(".dig [target_ip]");

		return true;
	}
	else if(op[1] == "stat")
	{
		const char *tunnelidstr = cmd.GetText(1);
		if(!tunnelidstr)
		{
			std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
			_LOG(_TunnelIdMap.size() << " tunnels:");
			for(auto &itor : _TunnelIdMap)
			{
				const std::shared_ptr<MLT_Tunnel> pTunnel = itor.second;
				const static char status[][15] = { "Disconnected", "Connected", "Closed" };
				uint32_t destId = pTunnel->GetDestinationTunnelId();
				_LOG(pTunnel->GetTunnelId() << " <---> " << (destId == 0xffffffff ? rt::String_Ref("?") : rt::tos::Number(destId)) << " (" << status[uint16_t(pTunnel->GetStatus())] << "): " << pTunnel->GetTunnelUID() << ", dest device: " << tos(pTunnel->GetDestinationDHTAddress()));
			}
		}
		else
		{
			uint32_t tunnelid;
			if(sscanf(tunnelidstr, "%d", &tunnelid) == 1)
			{
				std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
				auto itor = _TunnelIdMap.find(tunnelid);
				if(itor != _TunnelIdMap.end())
				{
					itor->second->PrintStatus();
				}
			}
		}

		return true;
	}
#if defined(PLATFORM_DEBUG_BUILD)
	else if(op[1] == "msg")
	{
		const char *idstr = cmd.GetText(1);
		uint32_t id;
		const char *lenstr = cmd.GetText(2);
		uint32_t len;
		if(idstr && sscanf(idstr, "%d", &id) == 1
			&& lenstr && sscanf(lenstr, "%d", &len) == 1)
		{
			uint8_t *randomData = new uint8_t[len];
			os::Randomize(randomData, len);
			auto& a = GetHasher();
			a.Update(randomData, len);
			HashValue h;
			a.Finalize(&h);
			_LOG("[MLT] Sending msg with SHA256: " << rt::tos::Base32CrockfordLowercaseOnStack<>(h));
			if(!SendTunnelMessage(MLT_TUNNEL_HANDLE(id), randomData, len, randomData, 0))
			{
				_LOG("[MLT] Sending msg failed immediately.");
			}
		}

		return true;
	}
	else if(op[1] == "file")
	{
		const char *idstr = cmd.GetText(1);
		uint32_t id;
		const char *lenstr = cmd.GetText(2);
		uint32_t len;
		const char *pristr = cmd.GetText(3);
		if(idstr && sscanf(idstr, "%d", &id) == 1
			&& lenstr && sscanf(lenstr, "%d", &len) == 1)
		{
			sec::DataBlock<32> fn;
			os::Randomize(&fn, sizeof(fn));
			_LOG("[MLT] Downloading file: " << rt::tos::Base32CrockfordLowercaseOnStack<>(&fn, 32));
			static uint32_t i = 0;
			if(!StartFileDownload(MLT_TUNNEL_HANDLE(id), fn, len, new DebugIncomingFileWriter("i_" + std::to_string(i++)), 100))
			{
				_LOG("[MLT] Downloading file failed immediately.");
			}
		}

		return true;
	}
	else if(op[1] == "close")
	{
		const char *idstr = cmd.GetText(1);
		uint32_t id;
		if(idstr && sscanf(idstr, "%d", &id) == 1)
			CloseTunnel(MLT_TUNNEL_HANDLE(id));

		return true;
	}
	else if(op[1] == "dump")
	{
		const char *idstr = cmd.GetText(1);
		uint32_t id;
		if(idstr && sscanf(idstr, "%d", &id) == 1)
		{
			std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
			auto itor = _TunnelIdMap.find(id);
			if(itor != _TunnelIdMap.end())
			{
				const std::shared_ptr<MLT_Tunnel> pTunnel = itor->second;
				pTunnel->DumpLog();
			}
		}

		return true;
	}
	else if(op[1] == "dig")
	{
		const char *ipaddr = cmd.GetText(1);
		{
			bool bValid = false;
			NetworkAddress addr;
			if(ipaddr != nullptr)
				bValid = TextToNetworkAddress(addr, ipaddr);
			else
			{
				if(_pCore->HasLSM())
				{
					LocalPeerList peers = _pCore->LSM().GetPeers();
					if(peers.Count > 0)
					{
						addr = peers.Peers[0];
						bValid = true;
						_LOG("Digging to first local peer " << tos(addr));
					}
				}
			}
			if(bValid)
			{
				DebugEvents *handler = new DebugEvents(this);
				MLT_TunnelCreateInfo info;
				info.App = 0;
				info.EventHandler = handler;
				rt::Randomizer rand(os::Timestamp::Get());
				rand.Randomize(&info.Secret, sizeof(info.Secret));
				rand.Randomize(&info.PerDeviceUniqueId, MLT_TunnelPDUID::LEN);
				info.DestinationDeviceAddr.Random();
				handler->_uniqueId = info.PerDeviceUniqueId;
				handler->_destAddr = info.DestinationDeviceAddr;

				NodeAccessPoints aps;
				aps.PublicCount.v4 = aps.PublicCount.v6 = 0;
				aps.LocalCount.v4 = aps.LocalCount.v6 = 0;
				aps.BouncerCount.v4 = aps.BouncerCount.v6 = 0;
				if(addr.IsIPv4())
				{
					aps.PublicCount.v4 = 1;
					*(IPv4 *)aps.GetPublicIPv4() = addr.IPv4();
				}
				if(addr.IsIPv6())
				{
					aps.PublicCount.v6 = 1;
					*(IPv6 *)aps.GetPublicIPv6() = addr.IPv6();
				}

				PacketBuf<> packetBuf;
				uint32_t testMagic = 0xdeadbeaf;
				packetBuf.AppendPOD(testMagic);
				packetBuf.AppendPOD(info.App);
				packetBuf.Append(&info.PerDeviceUniqueId, MLT_TunnelPDUID::LEN);
				DhtAddress ownAddr = _pCore->DHT().GetNodeId();
				packetBuf.Append(&ownAddr, DHT_ADDRESS_SIZE);
				packetBuf.AppendPOD(info.Secret);

				MLT_TUNNEL_HANDLE hTunnel = OpenTunnel(info, aps, rt::String_Ref(packetBuf.GetData(), packetBuf.GetLength()));
				// Theoretically this might cause crash, since the tunnel could already be closed immediately. The probability is really low though.
				handler->handle = uint32_t(hTunnel);
			}
		}
		return true;
	}
#endif 

	return false;
}

std::shared_ptr<MLT_Tunnel> MultiLinkTunnels::_FindTunnelFromHandle(MLT_TUNNEL_HANDLE tunnelHandle) const
{
	std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
	auto itor = _TunnelIdMap.find(uint32_t(tunnelHandle));
	if(itor == _TunnelIdMap.end())
		return nullptr;

	return itor->second;
}

bool MultiLinkTunnels::SendTunnelMessage(MLT_TUNNEL_HANDLE tunnelHandle, uint8_t *pData, uint32_t dataLen, void *pCookie, uint32_t priority)
{
	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	return pTunnel->QueueMessageSend(pData, dataLen, pCookie, priority);
}

MLT_FILE_DOWNLOAD_HANDLE MultiLinkTunnels::StartFileDownload(MLT_TUNNEL_HANDLE tunnelHandle, const MLT_FileHash &fileHash, uint64_t fileSize, MLT_IncomingFileWriter *pWriter, uint32_t priority)
{
	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
	{
		pWriter->Release();
		return MLT_FILE_DOWNLOAD_INVALID_HANDLE;
	}

	uint32_t taskId = pTunnel->QueueFileDownload(fileHash, fileSize, pWriter, priority);
	if(taskId == 0xffffffffu)
		return MLT_FILE_DOWNLOAD_INVALID_HANDLE;

	return MLT_FILE_DOWNLOAD_HANDLE(uint64_t(tunnelHandle) | uint64_t(taskId) << 32);
}

bool MultiLinkTunnels::StopFileDownload(MLT_TUNNEL_HANDLE tunnelHandle, MLT_FILE_DOWNLOAD_HANDLE fileDownloadHandle)
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE || fileDownloadHandle == MLT_FILE_DOWNLOAD_INVALID_HANDLE)
		return false;
	if(uint32_t(tunnelHandle) != (uint64_t(fileDownloadHandle) & 0xffffffffu))
		return false;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	return pTunnel->StopFileDownload(uint32_t(uint64_t(fileDownloadHandle) >> 32));
}

void MultiLinkTunnels::StopFileServing(MLT_TUNNEL_HANDLE tunnelHandle, MLT_OutgoingFileReader* reader)
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return;

	pTunnel->StopFileServing(reader);
	return;
}

bool MultiLinkTunnels::GetTunnelCreateInfo(MLT_TUNNEL_HANDLE tunnelHandle, MLT_TunnelCreateInfo &outInfo) const
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return false;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	pTunnel->GetCreateInfo(outInfo);
	
	return true;
}
	
bool MultiLinkTunnels::IsTunnelConnected(MLT_TUNNEL_HANDLE tunnelHandle) const
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return false;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	return pTunnel->GetStatus() == MLT_Tunnel::Status::Connected;
}

bool MultiLinkTunnels::GetTunnelIdleTime(MLT_TUNNEL_HANDLE tunnelHandle, uint32_t &noTaskTime, uint32_t &noTaskProgressTime) const
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return false;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	uint64_t noTaskTime64;
	uint64_t noTaskProgressTime64;
	pTunnel->GetIdleTime(noTaskTime64, noTaskProgressTime64);
	noTaskTime = uint32_t(noTaskTime64);
	noTaskProgressTime64 = uint32_t(noTaskProgressTime64);

	return true;
}

bool MultiLinkTunnels::GetTunnelDeviceAddress(MLT_TUNNEL_HANDLE tunnelHandle, DhtAddress& dev_out) const
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return false;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	dev_out = pTunnel->GetDestinationDHTAddress();
	return true;
}

bool MultiLinkTunnels::GetTunnelLatencyAndLossRate(MLT_TUNNEL_HANDLE tunnelHandle, uint32_t& latencyInMs, uint32_t& lossRateInPercentage, uint32_t sample_window) const
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return false;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	pTunnel->GetTunnelLatencyAndPacketLossRate(sample_window, latencyInMs, lossRateInPercentage);
	return true;
}

bool MultiLinkTunnels::GetFileDownloadStatus(MLT_TUNNEL_HANDLE tunnelHandle, MLT_FILE_DOWNLOAD_HANDLE fileDownloadHandle, MLT_FileDownloadStatus &outStatus)
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE || fileDownloadHandle == MLT_FILE_DOWNLOAD_INVALID_HANDLE)
		return false;
	if(uint32_t(tunnelHandle) != (uint64_t(fileDownloadHandle) & 0xffffffffu))
		return false;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return false;

	return pTunnel->GetDownloadStatus(uint32_t(uint64_t(fileDownloadHandle) >> 32), outStatus);
}

MLT_TUNNEL_HANDLE MultiLinkTunnels::GetTunnelHandle(const MLT_TunnelPDUID &uid, const DhtAddress &destAddr)
{
	std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
	auto itor = _TunnelUniqueIDMap.find(uid);
	if(itor == _TunnelUniqueIDMap.end())
		return MLT_TUNNEL_INVALID_HANDLE;
	auto itor2 = itor->second.find(destAddr);
	if(itor2 == itor->second.end())
		return MLT_TUNNEL_INVALID_HANDLE;

	return MLT_TUNNEL_HANDLE(itor2->second);
}

UINT MultiLinkTunnels::GetTunnelsById(const MLT_TunnelPDUID &uid, rt::BufferEx<MLT_Endpoint>& ret)
{
	std::shared_lock<std::shared_timed_mutex> lock(_TunnelMapMutex);
	auto itor = _TunnelUniqueIDMap.find(uid);
	if(itor == _TunnelUniqueIDMap.end())
		return 0;

	ret.ChangeSize(ret.GetSize() + itor->second.size());
	auto* p = ret.Begin() + (ret.GetSize() - itor->second.size());
	for(auto itor2 : itor->second)
		*p++ = { MLT_TUNNEL_HANDLE(itor2.second), itor2.first };

	return (UINT)itor->second.size();
}

int64_t MultiLinkTunnels::GetControlBlockNumDownloadedBytes(const uint8_t *pCB, uint32_t cbSize, uint64_t totalSize)
{
	return MLT_IncomingFile::GetControlBlockNumDownloadedBytes(pCB, cbSize, totalSize);
}

void MultiLinkTunnels::AddTunnelAccessPoint(MLT_TUNNEL_HANDLE tunnelHandle, const NetworkAddress& dest, const NetworkAddress& bouncer)
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return;

	pTunnel->CreateLinkAndSendHandshake(dest, &bouncer);
}

void MultiLinkTunnels::AddTunnelAccessPoint(MLT_TUNNEL_HANDLE tunnelHandle, const NetworkAddress& dest)
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return;

	pTunnel->CreateLinkAndSendHandshake(dest, nullptr);
}

void MultiLinkTunnels::AddTunnelAccessPoint(MLT_TUNNEL_HANDLE tunnelHandle, const NodeAccessPoints& aps)
{
	if(tunnelHandle == MLT_TUNNEL_INVALID_HANDLE)
		return;

	std::shared_ptr<MLT_Tunnel> pTunnel = _FindTunnelFromHandle(tunnelHandle);
	if(!pTunnel)
		return;

	pTunnel->CreateLinksFromAPs(aps);
}

} // namespace upw
