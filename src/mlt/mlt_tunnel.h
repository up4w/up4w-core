#pragma once
#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_link.h"
#include "mlt_message.h"
#include "mlt_file_transfer.h"


namespace upw
{

class MLT_Tunnel
{
	friend class MLT_Link;

public:
	enum class Status : uint8_t
	{
		Disconnected	= 0,			// no connected links, will automatically try to reconnect
		Connected		= 1,			// at least one link is connected
		Closed			= 2,			// explicitly closed by either party, will not try to reconnect unless 
	};

private:
	// assigned at creation
	const MLT_TunnelCreateInfo									_CreateInfo;
	const uint32_t												_TunnelId;
	const rt::String											_ConnectionData;

	const uint64_t												_TunnelCreationTime;

	Status														_Status = Status::Disconnected;
	bool														_bWantToExposeTunnelId = true;					// if true, our tunnel id is included unencrypted in every packet we receive, visible to bouncer. Saves a bit overhead when parsing packets.
	uint32_t													_DestinationTunnelId = 0xffffffff;				// tunnel id on the destination side
	uint64_t													_SessionId = 0xffffffffffffffffull;				// session id of the tunnel
	uint64_t													_DestinationSessionId = 0xffffffffffffffffull;	// session id of the tunnel on destination side

	uint32_t													_NextLinkId = 0;
	std::unordered_map<uint32_t, std::shared_ptr<MLT_Link>>			_IdToLinks;
	std::unordered_map<NetworkAddress, std::shared_ptr<MLT_Link>>	_AddrToLinks;
	std::unordered_set<uint32_t>								_ConnectedLinkIds;
	std::unordered_set<uint32_t>								_PendingDeleteLinkIds;
	std::deque<NetworkAddress>									_backupDirectLinkDestinations;
	std::deque<std::pair<NetworkAddress, NetworkAddress>>		_backupBouncerLinkDestinations;				// pair<bouncer, destination>
	constexpr static uint8_t									_MaximumConnectedLinks = 8;					// maintain at most this amount of connected links, otherwise try to drop low-quality links
	constexpr static uint8_t									_MinimumConnectedLinks = 4;					// maintain at least this amount of connected links, otherwise try to establish more

	uint32_t													_NextOutgoingTaskId = uint32_t(MLT_Packet::PKT_TUNNEL_DATA_HEADER::TunnelDataType::Max) + 1;
																											// id for next outgoing task (message / file), this should not overlap with TunnelDataType values
	std::multimap<uint32_t, std::shared_ptr<MLT_OutgoingMessage>, std::greater<uint32_t>> _OutgoingMessages;
	std::map<uint32_t, std::shared_ptr<MLT_IncomingMessage>>	_IncomingMessages;
	constexpr static uint32_t									_IncomingMessageTimeout = 5000;				// if no new slice for a message received in this period of time, drop it 
	std::set<uint32_t>											_previouslyReceivedMessages;				// messages that are already received previously, will reply with MessageAcknowledge if they come again

	std::map<uint32_t, std::shared_ptr<MLT_IncomingFile>>		_IncomingFiles;
	std::map<uint32_t, std::shared_ptr<MLT_OutgoingFile>>		_OutgoingFiles;
	std::set<uint32_t>											_previouslyReceivedFiles;					// files that are already received previously, will reply with FileAcknowledge if they come again

	uint32_t													_NextSendSN = 0;							// serial number of the next tunnel data to be sent.
	uint32_t													_NextAckCheckSN = 0;						// serial number of the next tunnel data to be checked for ack from receiver.
	uint32_t													_MaxAckedSN = 0;							// the largest ACKed packet that we sent, only used for debugging
	constexpr static uint32_t									_SendWindowBufferSize = 10240;				// the maximum window of sent packets pending ack from receiver
	static_assert(_SendWindowBufferSize % 64 == 0, "_SendWindowBufferSize must be multiple of 64");
	uint32_t													_SendWindowCurSize = 64;					// the current window of sent packets pending ack from receiver, the size should be proportional to bandwidth and latency. here just reserve a large one instead
	std::vector<bool>											_SentPacketAcked = std::vector<bool>(_SendWindowBufferSize, false);			// whether a sent packet is acked.
	std::vector<uint32_t>										_SentPacketTaskId = std::vector<uint32_t>(_SendWindowBufferSize, 0);		// which app data a sent packet belongs to, 0 indicates a tunnel internal control message.
	std::vector<uint32_t>										_SentPacketCustomData = std::vector<uint32_t>(_SendWindowBufferSize, 0);	// custom data used by the app data to locate the packet within the message, could be e.g. offset
	std::vector<uint32_t>										_SentPacketTime = std::vector<uint32_t>(_SendWindowBufferSize, 0);			// timestamp when the packet was sent, the real time is _TunnelCreationTime + _SendPacketTime
	std::vector<uint32_t>										_SentPacketAckTime = std::vector<uint32_t>(_SendWindowBufferSize, 0xffffffffu);	// timestamp when the packet was acked, used to calculate latency, the real time is _TunnelCreationTime + _SendPacketTime
	//uint32_t													_SentPacketTimeout = 2000;					// if ACK not receiving for sent packets within this time, the packet is considered lost. in ms.

	constexpr static uint32_t									_RecvWindowBufferSize = 10240;				// the maximum window of received packets to ack to sender
	static_assert(_RecvWindowBufferSize % 64 == 0, "_RecvWindowBufferSize must be multiple of 64");
	static_assert(_RecvWindowBufferSize <= MLT_Packet::PKT_BATCH_ACK::AckMaskMaxSizeInBytes * 8 , "_RecvWindowBufferSize too large to fit into PKT_BATCH_ACK");
	static_assert(_RecvWindowBufferSize >= _SendWindowBufferSize, "_RecvWindowBufferSize must not be smaller than _SendWindowBufferSize");
	uint32_t													_RecvSNLargest = 0;									// largest SN from received packets
	uint32_t													_RecvSNWaitingSmallest = 0;							// Do not report incoming packets with SN lower than this to the sender
	uint64_t													_RecvPacketBitMask[_RecvWindowBufferSize / 64];		// whether a packet is received
	uint64_t													_RecvPacketToAckBitMask[_RecvWindowBufferSize / 64];// whether a packet is yet to ack
	uint32_t													_LastUnackedPacketSN;								// SN of the last unacked packet received, 0xffffffffu if no packet received since last ACK
	uint64_t													_LastUnackedPacketRecvTime;							// Timestamp of the last received unacked packet
	uint32_t													_FirstUnackedPacketSN;								// SN of the first unacked packet received, 0xffffffffu if no packet received since last ACK
	uint64_t													_FirstUnackedPacketRecvTime;						// Timestamp of the first received packet after last ACK was sent
	uint32_t													_NumUnackedPackets;									// Number of received packets that haven't been included in a batch-ack packet yet

	uint64_t													_LastAccessPointPacketTs = 0;				// last time an access points packet was sent
	constexpr static uint16_t									_AccessPointPacketMinimalInterval = 5000;	// multiple access points packets are not expected to be sent within this period of time
	uint64_t													_LastFileCancelRequestPacketTs = 0;			// last time a FileCancelRequest packet was sent
	constexpr static uint16_t									_FileCancelRequestMinimalInterval = 1000;	// FileCancelRequest packets are not sent more frequently than this

	constexpr static uint16_t									_BatchAckPacketMinimalInterval = 100;			// QoS packets are not sent faster than this interval, unless old QoS data is going to be dropped
	uint64_t													_LastBatchAckPacketTs = 0;

	uint64_t													_NoTaskSince = 0;
	uint64_t													_NoTaskProgressSince = 0;

	MLT_ValueHistory<60>										_PacketAckedRecentHistory;						// number of acked packets at each of the past 60 seconds
	MLT_ValueHistory<60>										_PacketLostRecentHistory;						// number of lost packets at each of the past 60 seconds
	MLT_ValueHistory<60>										_PacketLatencyRecentHistory;					// latency history of the past 60 seconds
	MLT_ValueHistory<60>										_PacketLatencyEntryCountRecentHistory;			// number of latency entries in each of the past 60 seconds
	uint32_t													_SRTT = 0;										// Smooth RTT
	uint32_t													_DevRTT = 0;									// Deviance RTT
	uint32_t													_RTO = 10000;									// RTO

	std::vector<std::string>									_Log;
	std::vector<bool>											_PacketAckHistory;

	os::CriticalSection		_CS;
	NetworkServiceCore		*_pCore;

private:
	std::shared_ptr<MLT_Link> _CreateLink(const NetworkAddress &dstAddr, const NetworkAddress *bouncerAddr);
	void _OnRecvTunnelData(const uint8_t *pData, uint16_t dataLen);
	void _ProcessIncomingPacketQoS(MLT_Packet::PKT_TUNNEL_DATA_HEADER *pHeader);
	void _OnLinkConnect(uint32_t linkId);
	void _OnLinkDisconnect(uint32_t linkId);

	void _SendCloseTunnelPacket();
	void _SendAccessPointsPacket();
	void _SendBatchAckPacket(bool bForce);

	bool _SendMessageDataPacket(uint32_t msgId, uint32_t dataTotalLen, uint32_t sliceIdx, const uint8_t *pSlice, uint16_t sliceLen);
	bool _SendMessageAcknowledgePacket(uint32_t msgId);
	void _SendMessageRejectPacket(uint32_t msgId);

	bool _SendFileRequestBlockPacket(const MLT_FileHash &fileHash, uint64_t fileSize, uint32_t fileId, uint32_t priority, uint32_t blockIdx, const uint8_t *sliceMask, uint16_t sliceMaskLen);
	bool _SendFileSlicePacket(uint32_t fileId, uint32_t sliceIdx, const uint8_t *pSlice, uint16_t sliceLen);
	bool _SendFileAcknowledgePacket(uint32_t fileId);
	bool _SendFileRejectRequestPacket(uint32_t fileId, uint32_t blockIdx);
	bool _SendFileCancelRequestPacket(uint32_t fileId);

	bool _SendTunnelData(MLT_Packet::PKT_TUNNEL_DATA_HEADER *pHeaderAndData, uint16_t totalLen, bool bWithSN, bool bOverAllLinks, uint32_t taskId, uint32_t msgCustomData);
	void _MaintainConnectedLinkList(uint32_t tick_in_100ms);
	void _RemoveLink(uint32_t linkId);
	void _AddBackupLink(std::shared_ptr<MLT_Link> pLink);
	void _PerformNextAckCheck(bool bForcePopFront, bool bForcePopAll);
	void _SendFileRequests();
	void _SendMessageAcknowledges();
	void _SendQueuedMessages();
	void _SendQueuedFiles();
	bool _IsSendWindowFull();
	void _SendQueuedData();
	void _ResetFlags();					// resets internal flags to assume that the destination doesn't know anything about this tunnel anymore
	void _ResetRecvBuffer();
	uint64_t _GetSessionId() { return _SessionId; }
	uint64_t _GetDestinationSessionId() { return _DestinationSessionId; }
	bool _ProcessIncomingSessionId(uint64_t incomingSenderSessionId, uint64_t incomingRecipientSessionId, bool& outShouldNotifyNewSessionId, bool &outShouldProcessTunnelData);		// returns false if the packet should be ignored
	void _OnDestinationSessionIdChange(uint64_t newDestinationSessionId);
	uint16_t _GetFastestLinkLatency() const;		// returns 0xffff if no connected link exists
	uint16_t _GetLatency(uint8_t range) const;		// include data from past range seconds
	void _UpdateRTT(uint32_t newRTTSample);

public:
	MLT_Tunnel(NetworkServiceCore* p, const MLT_TunnelCreateInfo &createInfo, uint32_t tunnelId, const rt::String_Ref &connectionData);
	~MLT_Tunnel();

	Status GetStatus() const { return _Status; }

	void Close(bool bClosedByDestination, bool bNotifyDestination);

	void OnTick(uint32_t tick_in_100ms, int64_t net_ts_in_ms);
	void OnRecv(MLT_IncomingPacketParser &parser, const NetworkAddress &senderAddr, const NetworkAddress *pBouncerAddr);

	void CreateLinksFromAPs(const NodeAccessPoints& aps);
	bool CreateLinkAndSendHandshake(const NetworkAddress &dstAddr, const NetworkAddress *bouncerAddr);

	uint32_t GetTunnelId() const { return _TunnelId; }
	MLT_TUNNEL_HANDLE GetHandle() const { return (MLT_TUNNEL_HANDLE)_TunnelId; }
	uint32_t GetDestinationTunnelId() const { return _DestinationTunnelId; }
	const MLT_TunnelPDUID& GetTunnelUID() const { return _CreateInfo.PerDeviceUniqueId; }
	const DhtAddress& GetDestinationDHTAddress() const { return _CreateInfo.DestinationDeviceAddr; }
	const MLT_TunnelCipherSecret& GetCipherSecret() const { return _CreateInfo.Secret; }
	uint8_t GetAppId() const { return _CreateInfo.App; }
	void GetCreateInfo(MLT_TunnelCreateInfo &outInfo) const;

	bool QueueMessageSend(const uint8_t *pData, uint32_t dataLen, void *pCookie, uint32_t priority);

	//returns the internal id allocated for the task, returns 0xffffffffu if not queued
	uint32_t QueueFileDownload(const MLT_FileHash &fileHash, uint64_t fileSize, MLT_IncomingFileWriter *pWriter, uint32_t priority);
	bool StopFileDownload(uint32_t fileId);
	bool GetDownloadStatus(uint32_t fileId, MLT_FileDownloadStatus &outStatus);
	void StopFileServing(MLT_OutgoingFileReader *pReader);

	void GetIdleTime(uint64_t &noTaskTime, uint64_t &noTaskProgressTime) const;
	void GetTunnelLatencyAndPacketLossRate(uint32_t range, uint32_t &latencyInMs, uint32_t &lossRateInPercentage_100x) const;	// range: include data from the past range seconds
	bool IsBusy();

	void Awaken();		// put the tunnel status from closed to disconnected

	void DumpLog();
	void PrintStatus();
};

} // namespace upw