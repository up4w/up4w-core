#pragma once
#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

namespace upw
{

enum MLT_TUNNEL_HANDLE : int32_t { MLT_TUNNEL_INVALID_HANDLE = -1 };
enum MLT_FILE_DOWNLOAD_HANDLE : int64_t { MLT_FILE_DOWNLOAD_INVALID_HANDLE = -1 };

typedef sec::DataBlock<32>				MLT_TunnelPDUID;  // tunnel per-destination unique id
typedef sec::DataBlock<32,true>			MLT_TunnelCipherSecret;
typedef sec::Cipher<sec::CIPHER_AES256> MLT_TunnelCipher;
typedef sec::DataBlock<32>				MLT_FileHash;

struct MLT_IncomingFileWriter
{
	// control data is a block of custom data that used to store download progress, which could later be used to resume download
	virtual bool SetControlData(const uint8_t *controlData, uint32_t controlDataLen) = 0;	// store control data, expected size is about 1 - 1.5KB
	virtual bool GetControlData(const uint8_t **data_out, uint32_t *outControlDataLen) = 0;	// get the last stored control data. returns false only if control data exists but fails to be loaded. if control data doesn't exist, return true, but set data_out to nullptr
																							// caller should not keep *data_out or release the memory
	virtual bool Write(uint64_t offset, uint8_t *data, uint32_t dataLen) = 0;				// write data of length dataLen to file at offset
	virtual void FinalizeWrite() = 0;														// all file content have been written, do some cleanup of intermediate data, e.g. control data
	virtual void Release() = 0;																// called when the tunnel no longer needs the writer
};

struct MLT_OutgoingFileReader
{
	virtual uint32_t Read(uint64_t offset, uint32_t readLen, uint8_t *pBuffer) = 0;		// read readLen bytes starting from offset, pBuffer is guaranteed to have at least readLen bytes, returns the number of bytes read.
	//virtual void Release() = 0;															// called when the tunnel no longer needs the reader
};

struct MLT_TunnelEventHandler
{
	enum FDI_Reason
	{
		FDI_TunnelClose,			// tunnel is closed
		FDI_TunnelDisconnect,		// tunnel is disconnected
		FDI_LocalWriteError,		// local control data is corrupted
		FDI_LocalControlDataError,	// failed to write data to disk (possibly disk full)
		FDI_Rejected,				// the sender actively rejected our request
		FDI_Cancelled,				// download task actively canceled by user
	};

	virtual void OnMessageSent(void *pMsgCookie, bool bSuccessfullyDelivered){}
	virtual void OnMessageReceived(const uint8_t *pData, uint32_t dataLen){}
	virtual void OnFileDownloaded(MLT_TUNNEL_HANDLE h, const MLT_FileHash &hash){}
	virtual void OnFileDownloadInterrupted(MLT_TUNNEL_HANDLE h, const MLT_FileHash &hash, FDI_Reason reason){}

	// for a specific MLT_TUNNEL_HANDLE, there will be only one reader for each file hash
	virtual MLT_OutgoingFileReader* OnFileRequest(MLT_TUNNEL_HANDLE h, const MLT_FileHash &fileHash, uint64_t fileSize){ return nullptr; }
	virtual void OnFileUnrequest(MLT_TUNNEL_HANDLE h, MLT_OutgoingFileReader* reader){}

	virtual void OnConnected(MLT_TUNNEL_HANDLE h){}
	virtual void OnDisconnected(MLT_TUNNEL_HANDLE h, bool bClosedByDestination){}
	virtual void OnLinkConnected(MLT_TUNNEL_HANDLE h, const NetworkAddress &senderAddr, const NetworkAddress *pBouncerAddr) {}
	virtual void OnLinkDisconnected(MLT_TUNNEL_HANDLE h, const NetworkAddress &senderAddr, const NetworkAddress *pBouncerAddr) {}

	virtual void OnAttach(MLT_TUNNEL_HANDLE h){};
	virtual void OnDetach(MLT_TUNNEL_HANDLE h){};
};

struct MLT_TunnelCreateInfo
{
	uint8_t						App;
	DhtAddress					DestinationDeviceAddr;
	MLT_TunnelPDUID				PerDeviceUniqueId;
	MLT_TunnelCipherSecret		Secret;
	MLT_TunnelEventHandler*		EventHandler;				// per-tunnel event handler
};

struct MLT_FileDownloadStatus
{
	MLT_FileHash			fileHash;
	uint64_t				fileSize;
	uint64_t				downloadedSize;
	uint64_t				downloadSpeed;
};

struct MLT_AppCallback
{
	virtual bool IdentifyIncomingConnection(void* connection_data, uint32_t connection_data_len, MLT_TunnelPDUID* out_id, DhtAddress *out_dest_addr) = 0;	// extract the tunnel unique id from incoming connection data
	virtual bool ResolveIncomingConnection(void* connection_data, uint32_t connection_data_len, MLT_TunnelCreateInfo* in_out_create_info) = 0;	// extract the tunnel create info from incoming connection data, in_out_create_info.UniqueID should be pre-filled.
};

struct MLT_Endpoint
{
	MLT_TUNNEL_HANDLE	handle;
	DhtAddress			device;
};

} // namespace upw