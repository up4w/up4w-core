#pragma once
#include <shared_mutex>

#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_tunnel.h"


namespace upw
{

// Multi-Link 0/1-hop relayed Tunnel peer to peer connection, designed for live-stream communication for 1:1 audio/video
// Tunnel is connection-oriented but has datagram boundary, is unbuffered, unreliable (packet may lost) and order-inconsistent (packet may jitter)
// Tunnel can be AES Encrypted but unchained

class MultiLinkTunnels
{
	NetworkServiceCore*	_pCore;

protected:
	MLT_AppCallback												*_AppCallbacks[256];
	std::map<MLT_TunnelPDUID, std::map<DhtAddress, uint32_t>>	_TunnelUniqueIDMap;
	std::map<uint32_t, std::shared_ptr<MLT_Tunnel>>				_TunnelIdMap;
	uint32_t													_NextTunnelId = 0;
	mutable std::shared_timed_mutex								_TunnelMapMutex;
	bool														_bBusy = false;

	bool	_OnExecuteCommand(const os::CommandLine& cmd, rt::String& out);
	bool	_ResolveIncomingConnection(void* connection_data, uint32_t connection_data_len, uint8_t app_id, MLT_TunnelCreateInfo* out_create_info);
	bool	_IdentifyIncomingConnection(void* connection_data, uint32_t connection_data_len, uint8_t app_id, MLT_TunnelPDUID* id_out, DhtAddress *dest_addr_out);

	void	_OnRecv(const void* pData, UINT len, const PacketRecvContext& ctx);
	void	_OnTick(UINT tick_in_100ms, LONGLONG net_ts_in_ms);

	std::shared_ptr<MLT_Tunnel> _CreateTunnel(const MLT_TunnelCreateInfo& init, const rt::String_Ref& connectionData);
	std::shared_ptr<MLT_Tunnel> _FindTunnelFromHandle(MLT_TUNNEL_HANDLE tunnelHandle) const;

public:
	MultiLinkTunnels(NetworkServiceCore* p);
	~MultiLinkTunnels();

	void						SetIncomingConnectionCallback(uint8_t app, MLT_AppCallback *call_back);
	MLT_TUNNEL_HANDLE			OpenTunnel(const MLT_TunnelCreateInfo& init, const NodeAccessPoints& aps, const rt::String_Ref& connection_data);
	void						AddTunnelAccessPoint(MLT_TUNNEL_HANDLE tunnelHandle, const NodeAccessPoints& aps);
	void						AddTunnelAccessPoint(MLT_TUNNEL_HANDLE tunnelHandle, const NetworkAddress& dest);
	void						AddTunnelAccessPoint(MLT_TUNNEL_HANDLE tunnelHandle, const NetworkAddress& dest, const NetworkAddress& bouncer);
	void						CloseTunnel(MLT_TUNNEL_HANDLE handle);
	void						CloseTunnel(const MLT_TunnelPDUID &uid, const DhtAddress &destDHTAddr);
	void						CloseTunnels(const MLT_TunnelPDUID &uid); // close all tunnels with the uid
	bool						SendTunnelMessage(MLT_TUNNEL_HANDLE handle, uint8_t *pData, uint32_t dataLen, void *pCookie, uint32_t priority);  // if return true, pData will be hold until OnMessageSent

	// returns MLT_FILE_DOWNLOAD_INVALID_HANDLE in two cases:
	// 1. failed to start the download
	// 2. the file was already downloaded when.
	MLT_FILE_DOWNLOAD_HANDLE	StartFileDownload(MLT_TUNNEL_HANDLE tunnelHandle, const MLT_FileHash &fileHash, uint64_t fileSize, MLT_IncomingFileWriter *pWriter, uint32_t priority);
	bool						StopFileDownload(MLT_TUNNEL_HANDLE tunnelHandle, MLT_FILE_DOWNLOAD_HANDLE fileDownloadHandle);
	void						StopFileServing(MLT_TUNNEL_HANDLE tunnelHandle, MLT_OutgoingFileReader* reader);

	bool						GetTunnelCreateInfo(MLT_TUNNEL_HANDLE tunnelHandle, MLT_TunnelCreateInfo &outInfo) const;
	bool						IsTunnelConnected(MLT_TUNNEL_HANDLE tunnelHandle) const;
	bool						GetTunnelIdleTime(MLT_TUNNEL_HANDLE tunnelHandle, uint32_t &noTaskTime, uint32_t &noTaskProgressTime) const; // TBD, idle time in second
	bool						GetTunnelDeviceAddress(MLT_TUNNEL_HANDLE tunnelHandle, DhtAddress& dev_out) const;
	bool						GetTunnelLatencyAndLossRate(MLT_TUNNEL_HANDLE tunnelHandle, uint32_t& latencyInMs, uint32_t& lossRateInPercentage, uint32_t sample_window = 15) const;	// range: include data from the past range seconds

	bool						GetFileDownloadStatus(MLT_TUNNEL_HANDLE tunnelHandle, MLT_FILE_DOWNLOAD_HANDLE fileDownloadHandle, MLT_FileDownloadStatus &outStatus);
	MLT_TUNNEL_HANDLE			GetTunnelHandle(const MLT_TunnelPDUID &uid, const DhtAddress &destAddr);
	UINT						GetTunnelsById(const MLT_TunnelPDUID &uid, rt::BufferEx<MLT_Endpoint>& out_append);		// return # of endpoints appended
	static int64_t				GetControlBlockNumDownloadedBytes(const uint8_t *pCB, uint32_t cbSize, uint64_t totalSize);		// returns -1 if control block unrecognizable
};

} // namespace upw