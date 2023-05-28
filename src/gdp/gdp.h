#pragma once

#include "gdp_base.h"
#include "gdp_buf.h"
#include "gdp_task.h"
#include "gdp_message.h"


namespace upw
{

class NetworkServiceCore;
class SwarmBroadcast;

class GossipDataPropagation
{
	friend class GdpDownloadTask;
public:
	THISCALL_POLYMORPHISM_DECLARE(bool, true, OnDataRecvAssembled, GdpDataInMem* data, const GdpHint& hint);
	THISCALL_POLYMORPHISM_DECLARE(bool, true, OnDataRecvUnfragmented, const GdpHash& hash, const GdpHint& hint, LPBYTE data, UINT data_len);
	THISCALL_POLYMORPHISM_DECLARE(GdpDataMemLayout, (GdpDataMemLayout)0, OnDataDiscovered, const GdpHash& hash, const GdpHint& hint, LPCBYTE sample, UINT sample_len, UINT data_len);
	THISCALL_POLYMORPHISM_DECLARE(GdpDataPage*, nullptr, OnDataRequest, const GdpHash& hash, const GdpHint& hint, UINT page_no);
	void SetOnDataCallback(UINT module, LPVOID obj, const THISCALL_MFPTR& recv_assembled = nullptr, const THISCALL_MFPTR& recv_unfragmented = nullptr, const THISCALL_MFPTR& discover = nullptr, const THISCALL_MFPTR& request = nullptr);

protected:
	struct CallbackEntry
	{	LPVOID				Object;
		THISCALL_MFPTR		OnDataRecvAssembled;
		THISCALL_MFPTR		OnDataRecvUnfragmented;
		THISCALL_MFPTR		OnDataDiscovered;
		THISCALL_MFPTR		OnDataRequest;
	};

	CallbackEntry			_DataCallbacks[8]; // GdpHint::Module => Callback

	// push data to upper level, call this when a data block is assembled completely
	// upper level return false if the data is invalid
	// callee is responsible for releasing the data pointer
	bool _OnDataRecvAssembled(GdpDataInMem* data, const GdpHint& hint){ auto& e = _DataCallbacks[hint.Module]; return THISCALL_POLYMORPHISM_INVOKE(OnDataRecvAssembled, e.Object, e.OnDataRecvAssembled, data, hint); }
	// push pure data without prefix/suffix, upper will check, alloc, store....
	// upper level return false if the data is invalid
	bool _OnDataRecvUnfragmented(const GdpHash& hash, const GdpHint& hint, LPBYTE data, UINT data_len){ auto& e = _DataCallbacks[hint.Module]; return THISCALL_POLYMORPHISM_INVOKE(OnDataRecvUnfragmented, e.Object, e.OnDataRecvUnfragmented, hash, hint, data, data_len); }
	// check with upper level if the data needs to be downloaded, return PrefixSize(high 32-bits) & SuffixSize(low 32-bits)
	GdpDataMemLayout _OnDataDiscovered(const GdpHash& hash, const GdpHint& hint, LPCBYTE sample, UINT sample_len, UINT data_len){ auto& e = _DataCallbacks[hint.Module]; return THISCALL_POLYMORPHISM_INVOKE(OnDataDiscovered, e.Object, e.OnDataDiscovered, hash, hint, sample, sample_len, data_len); }
	// request data by key from upper level
	GdpDataPage* _OnDataRequest(const GdpHash& hash, const GdpHint& hint, UINT page_no){	auto& e = _DataCallbacks[hint.Module]; return THISCALL_POLYMORPHISM_INVOKE(OnDataRequest, e.Object, e.OnDataRequest, hash, hint, page_no); }

public:
	GossipDataPropagation(NetworkServiceCore* c, UINT worksize = 0);
	~GossipDataPropagation();

	UINT	Join(const DhtAddress& target, UINT swarm_size, const rt::String_Ref& boot_file = nullptr);	// return swarm_id (SWARM_ID_INVALID if failed)
	void	Leave(UINT swarm_id);

	int		Broadcast(UINT swarm_id, LPCBYTE data, UINT len, const GdpHash& hash, const GdpHint& hint, UINT push_count = GDP_AUTO_PUSH_COUNT);
	int		BroadcastColdData(UINT swarm_id, GdpDataPage* firstpage, const GdpHash& hash, const GdpHint& hint);
	int		Send(LPCBYTE data, UINT len, const GdpHash& hash, const GdpHint& hint, const NetworkAddress& to);

	void	Request(UINT swarm_id, const GdpHash* hashes, UINT hash_count, const GdpHint& hint, const GdpOptions& opt);
	void	SetPriorityBarForBusyEvent(UINT p){ _PriorityBarForBusyEvent = rt::min(p, 255U); } // affect NETWORK_GDP_PRIORITY_BUSY/NETWORK_GDP_PRIORITY_IDLE event
			// adding any GDP task having Priority >= _PriorityBarForBusyEvent will trigger NETWORK_GDP_PRIORITY_BUSY event
			// complete/cancel/timeout of the last GDP task having Priority >= _PriorityBarForBusyEvent will trigger NETWORK_GDP_PRIORITY_IDLE event

	void	RemoveHotData(const GdpHash& hash, const GdpHint& hint);	// only hot data will be removed
	void	RemoveHotData(const GdpHash& hash);
	void	RemoveAllHotData();
	bool	IsHotDataCached(const GdpHash& hash);

public:
	void	EnableCommand();
	bool	GetStateReport(rt::String& out);
	bool	DownloadTaskExist(const GdpHash& hash, const GdpHint& hint);
	bool	QueryDownloadTask(const GdpHash& hash, const GdpHint& hint, GdpDownloadTaskStatus& status);
	bool	RemoveDownloadTask(const GdpHash& hash, const GdpHint& hint);
	void	SetWorkSize(UINT val) { _WorkSize = val; }

	void	GetWorkload(rt::String& out);
	auto	GetWorkload() -> GdpWorkload;

protected:
	volatile bool				_WantExit = false; 
	GdpCounter					_WorkThreadCT;	

	NetworkServiceCore*			_pCore;
	SwarmBroadcast*				_pSMB;

	UINT						_PriorityBarForBusyEvent = 255;
	GdpDownloadTaskManager		_DownloadManager;
	GdpDataBufferManager		_DataManager;
	GdpProbeTasks				_ProbeTasks;
	GdpBroadcastTasks			_BroadcastTasks;
	UINT						_WorkSize = 0;	// 0:unlimited
	bool						_Busy = false;

	void	_OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& ctx); // hook up with NetworkServiceCore for receiving data
	void	_OnTick(UINT tick);												// hook up with NetworkServiceCore for driving task
	bool	_OnCommand(const os::CommandLine& cmd, rt::String& out);		// hook up with NetworkServiceCore for command prompt, gdp.report

	void	_OnRecv_MessageContent(LPBYTE pData, UINT len, const PacketRecvContext& ctx); // called by _OnRecv() for: GOC_MESSAGE_CONTENT
	void	_OnRecv_MessagePull(LPBYTE pData, UINT len, const PacketRecvContext& ctx);	// called by _OnRecv() for: GOC_MESSAGE_PULL

	void	_OnRecv_Req_Batch(LPBYTE pData, UINT len, const PacketRecvContext& ctx);

	bool	_ReadData(GdpPieceRecord& record);
	bool	_SendPacket(Packet& packet, const NetworkAddress& to, PACKET_SENDING_FLAG flag = PSF_NORMAL);
	int		_BroadcastPacket(Packet& packet, UINT swarm_id, const NetworkAddress* skip = nullptr, PACKET_SENDING_FLAG flag = PSF_NORMAL);

	void	_RecordRecvInvalidData(LPCVOID pData, UINT len);

	void	_RecordBroadcastData(const GdpHash& hash, const GdpHint& hint, const UINT offset, const UINT length);
	void	_RecordBroadcastTask(const GdpHash& hash, const GdpHint& hint, const UINT size);


protected:
	struct _GossipStatistics
	{
		volatile __int64 TotalSentPacket;
		volatile __int64 TotalSentBytes;

		volatile __int64 TotalBroadcastPacket;
		volatile __int64 TotalBroadcastBytes;

		volatile __int64 TotalRecvPacket;
		volatile __int64 TotalRecvBytes;
		
		volatile __int64 TotalInvalidPacket;
		volatile __int64 TotalInvalidBytes;

		volatile __int64 TaskFinished;
		volatile __int64 TaskRejected;
	};
	_GossipStatistics Statistics;
};

} // namespace upw

