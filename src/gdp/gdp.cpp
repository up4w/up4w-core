
#include "../../externs/miniposix/core/ext/botan/botan.h"
#include "../api/local_api.h"
#include "../dht/dht.h"
#include "../swarm_broadcast.h"

#include "gdp.h"
#include "gdp_message.h"
#include "gdp_task.h"
#include "gdp_buf.h"

namespace upw
{

#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#pragma message("GDP Hint Size : " __STR1__(GDP_HINT_SIZE))
#undef __STR1__
#undef __STR2__

void GossipDataPropagation::SetOnDataCallback(UINT module, LPVOID obj, const THISCALL_MFPTR& recv_assembled, const THISCALL_MFPTR& recv_unfragmented, const THISCALL_MFPTR& discover, const THISCALL_MFPTR& request)
{
	ASSERT(module < 8);  // max value of GdpHint::Module
	auto& cb = _DataCallbacks[module];
	cb = { obj, recv_assembled, recv_unfragmented, discover, request };
}

GossipDataPropagation::GossipDataPropagation(NetworkServiceCore* c, UINT worksize)
	:_pCore(c), _WorkSize(worksize)
{
	_pCore->SetPacketOnRecvCallBack(NET_PACKET_HEADBYTE_GDP, this, &GossipDataPropagation::_OnRecv);
	_pCore->SetOnTickCallback(this, &GossipDataPropagation::_OnTick);

	ASSERT(_pCore->HasSMB());
	_pSMB = &_pCore->SMB();
	ASSERT(_pSMB);

	rt::Zero(_DataCallbacks);
	rt::Zero(Statistics);

	GDP_LOG(
		"GossipDataPropagation::GossipDataPropagation()"
	);
}

bool GossipDataPropagation::DownloadTaskExist(const GdpHash& hash, const GdpHint& hint)
{
	if(_ProbeTasks.Exist(GdpKey(hash, hint)))
		return true;

	if(_DownloadManager.Exist(GdpKey(hash, hint)))
		return true;

	return false;
}

bool GossipDataPropagation::QueryDownloadTask(const GdpHash& hash, const GdpHint& hint, GdpDownloadTaskStatus& status)
{ 
	return _DownloadManager.Query(GdpKey(hash, hint), status);
};

bool GossipDataPropagation::RemoveDownloadTask(const GdpHash& hash, const GdpHint& hint)
{
	if(_ProbeTasks.Remove(GdpKey(hash, hint)))
		return true;

	return _DownloadManager.Delete(GdpKey(hash, hint), TDR_USER);
};

void GossipDataPropagation::_OnRecv(LPCVOID pData, UINT len, const PacketRecvContext& recv_ctx)
{
	static thread_local GdpPacketContext ctx;

	if(_WantExit||recv_ctx.pRelayPeer)return;

#ifndef	NDEBUG
	// random drop packets to simulate network
	if(_GDP_LOSS_RATE_)
	{
		static rt::Randomizer rng(os::TickCount::Get());
		if(rng.GetNext() % 1000 < _GDP_LOSS_RATE_)
		{
			GDP_TRACE("Drop Packet!");
			return;
		}
	}
#endif

	GDP_AUTO_COUNT(_WorkThreadCT);

	os::AtomicAdd(len, &Statistics.TotalRecvBytes);
	os::AtomicIncrement(&Statistics.TotalRecvPacket);

	GdpPacketHeader* lpHeader = (GdpPacketHeader*)pData;

	switch (lpHeader->OpCode)
	{

	case GOC_MESSAGE_CONTENT:
		_OnRecv_MessageContent((LPBYTE)pData, len, recv_ctx); 
		break;

	case GOC_MESSAGE_PULL:
		_OnRecv_MessagePull((LPBYTE)pData, len, recv_ctx);
		break;

	case GOC_Req_Batch:
		_OnRecv_Req_Batch((LPBYTE)pData, len, recv_ctx);
		break;

	default:
		GDP_TRACE("Unknown Gossip OP Code:"<< lpHeader->OpCode);
		_RecordRecvInvalidData(pData, len);
	}
}

void GossipDataPropagation::_OnRecv_Req_Batch(LPBYTE pData, UINT len, const PacketRecvContext& ctx)
{
	// check error format 
	GdpPacketReqBatch* lpHeader = (GdpPacketReqBatch*)pData;

	if( len < sizeof(GdpPacketReqBatch) ||
		 lpHeader->Count > GDP_PACKET_MAX_KEYS ||
		len < sizeof(GdpPacketReqBatch) + sizeof(GdpKey) * lpHeader->Count
		)
	{
		_RecordRecvInvalidData(pData, len);
		return;
	}

	LPBYTE pCount = pData + sizeof(GdpPacketHeader);
	const BYTE& count = *pCount;

	GdpKey* keys = (GdpKey*) (pData + sizeof(GdpPacketHeader) + 1);
	
	PacketBuf<>buf;

	for(UINT i = 0; i < count; i++)
	{
		
		GdpPieceRecord record;
		record.Hash = &keys[i].Hash;
		record.Hint = keys[i].Hint;
		record.Offset = 0;
		record.Length = 0;

		bool r = _ReadData(record);

		if(r == false)	continue;

		// todo:  can be optimized
		r = GdpBuildMessageContentPacket(*record.Hash, record.Hint, record.DataTotalSize, record.Offset, record.DataLen, record.Data, buf);

		_SendPacket(buf, ctx.RecvFrom);
		_RecordBroadcastData(*record.Hash, record.Hint, record.Offset, record.DataLen);
	}
}


void GossipDataPropagation::_OnRecv_MessageContent(LPBYTE pData, UINT len, const PacketRecvContext& ctx)
{
	GdpPacketHeader* lpHeader = (GdpPacketHeader*)pData;
	GdpPacketMessageContent* lpContent = (GdpPacketMessageContent*)(pData + sizeof(GdpPacketHeader));

	//check error format 
	if((len < sizeof(GdpPacketHeader) + sizeof(GdpPacketMessageContent) - 1) ||
		(lpContent->Length > GDP_BLOB_NONPAGED_MAXSIZE) ||
		(lpContent->DataTotalSize > GDP_BLOB_MAXSIZE) ||
		(lpContent->Offset + lpContent->Length > lpContent->DataTotalSize))
	{
		_RecordRecvInvalidData(pData, len);
		return;
	}
		
	if(lpContent->DataTotalSize <= GDP_BLOB_NONPAGED_MAXSIZE)
	{
		if(lpContent->Offset != 0)
		{
			_RecordRecvInvalidData(pData, len);
			return;
		}

		if(lpContent->Length == 0)
		{
			PacketBuf<>buf;
			GdpBuildMessagePullPacketWithHint(lpContent->Hash, lpContent->Hint, 0, lpContent->DataTotalSize, buf);
			_SendPacket(buf, ctx.RecvFrom);
		}
		else if(lpContent->Length == lpContent->DataTotalSize)
		{
			bool accepted = false;

			// skip hash check if GDPOPT_CUSTOMIZED_KEY in GdpOptionsFlags
			GdpHash datahash;
			datahash.Hash(lpContent->Data, lpContent->DataTotalSize);

			bool need_check = true;
			TaskInfoPtr info = _ProbeTasks.RemoveAndGetPtr(GdpKey(lpContent->Hash, lpContent->Hint));

			if(info && info->IsCustomizedKey())
					need_check = false;
			
			if(need_check == false)
			{
				accepted = this->_OnDataRecvUnfragmented(lpContent->Hash, lpContent->Hint, lpContent->Data, lpContent->DataTotalSize);
			}
			else
			{
				//if(datahash == lpContent->Hash)
				{
					accepted = this->_OnDataRecvUnfragmented(lpContent->Hash, lpContent->Hint, lpContent->Data, lpContent->DataTotalSize);
					ASSERT(accepted); // gdp checked data should be accepted
				}
				//else
				//{
				//	GDP_TRACE("Hash Unmatch Data!");
				//}
			}
			 
			if(accepted == false)
				os::AtomicIncrement(&Statistics.TaskRejected);

			// NoExpiration task will be recreated if not be accepted
			if(accepted == false && info && info->IsNoExpiration())
			{
				this->Request(info->Swarm_Id, &info->Key.Hash, 1, info->Key.Hint, info->Options);
			}

				
		}
		else
		{
			_RecordRecvInvalidData(pData, len);
			return;
		}
	}
	else
	{
		GDP_TRACE("Recv Data   offset:" << lpContent->Offset << "	Len:" << lpContent->Length);

		if(lpContent->Length + offsetof(GdpPacketMessageContent, Data) + sizeof(GdpPacketHeader) != len)
		{
			_RecordRecvInvalidData(pData, len);
			return;
		}
		
		DownloadTaskPtr pTask;
		GdpKey key(lpContent->Hash, lpContent->Hint);
 
		if(_DownloadManager.Find(key, pTask) == false)
		{
			// todo: create the task at once if GDPOPT_CUSTOMIZED_KEY in GdpOptionsFlags
			
			TaskInfoPtr info = _ProbeTasks.RemoveAndGetPtr(GdpKey(lpContent->Hash, lpContent->Hint));
			
			if(info)
				_DownloadManager.Add(key, lpContent->DataTotalSize, &(*info), pTask);
			else
				_DownloadManager.Add(key, lpContent->DataTotalSize, nullptr, pTask);
			
		}
		pTask->AddPeer(ctx.RecvFrom);

		if(pTask->Valid() == false && lpContent->Offset == 0 && lpContent->Length > 0)
		{
			GdpDataMemLayout layout = this->_OnDataDiscovered(lpContent->Hash, lpContent->Hint, lpContent->Data, GDP_PACKET_FRAGMENT_SIZE, lpContent->DataTotalSize);
			if(layout == 0 || pTask->_TaskInfo.IsValidSize(lpContent->DataTotalSize) == false)
			{
				GDP_TRACE("Reject Task:" << GDP_BIN_TO_BASE16(lpContent->Hash));
				pTask->SetManageStatus(TMS_REJECTED);
				return;
			}
			else
			{
				pTask->SetManageStatus(TMS_ACCEPTED);
				pTask->Initialize(GdpGetPrefixSize(layout), GdpGetSuffixSize(layout), GDP_TASK_MAX_IDLE);
			}
	
		}
		
		pTask->OnData(lpContent->Offset, lpContent->Data, lpContent->Length, ctx.RecvFrom);
		
	}
}


void GossipDataPropagation::_OnRecv_MessagePull(LPBYTE pData, UINT len, const PacketRecvContext& ctx)
{
	GdpPacketHeader* lpHeader = (GdpPacketHeader*)pData;
	GdpPacketMessagePull* lpPull = (GdpPacketMessagePull*)(pData + sizeof(GdpPacketHeader));

	//check error format 
	if((len < sizeof(GdpPacketHeader) + sizeof(GdpPacketMessagePull)) ||
		(lpPull->Offset + lpPull->Length > GDP_BLOB_MAXSIZE))
	{
		_RecordRecvInvalidData(pData, len);
		return;
	}

	GDP_TRACE("Pull offset:" << lpPull->Offset << "	Len:" << lpPull->Length);
	
	GdpPieceRecord record;
	record.Hash = &lpPull->Hash;
	record.Hint = lpPull->Hint;
	record.Length = lpPull->Length;
	record.Offset = lpPull->Offset;

	if(lpPull->Offset == 0 && lpPull->Length == 4) // for echo
	{
		bool r = _ReadData(record);
		if(r == false)
			return;

		PacketBuf<>buf;
		UINT* lpTS = (UINT*)(pData + sizeof(GdpPacketHeader) + sizeof(GdpPacketMessagePull));
		r = GdpBuildMessageContentPacket(*record.Hash, record.Hint, record.DataTotalSize, 0, 4, (LPCBYTE)lpTS, buf);

		_SendPacket(buf, ctx.RecvFrom);
		return;
	}

	if(lpPull->Offset == 0 && lpPull->Length == 0) // for request
	{
		bool r = _ReadData(record);
		if(r == false)
			return;

		PacketBuf<>buf;
		r = GdpBuildMessageContentPacket(*record.Hash, record.Hint, record.DataTotalSize, record.Offset, record.DataLen, record.Data, buf);

		_SendPacket(buf, ctx.RecvFrom);
		_RecordBroadcastData(*record.Hash, record.Hint, record.Offset, record.DataLen);
		return;
	}

	record.Length = GDP_PACKET_FRAGMENT_SIZE;

	for(int ct = 0; ct<lpPull->Length; ct += GDP_PACKET_FRAGMENT_SIZE)
	{
		bool r = _ReadData(record);
		if(r == false)
			break;

		PacketBuf<>buf;
		r = GdpBuildMessageContentPacket(*record.Hash, record.Hint, record.DataTotalSize, record.Offset, record.DataLen, record.Data, buf);

		_SendPacket(buf, ctx.RecvFrom);
		_RecordBroadcastData(*record.Hash, record.Hint, record.Offset, record.DataLen);
		record.Offset += record.Length;
	}
}

UINT GossipDataPropagation::Join(const DhtAddress& target, UINT swarm_size, const rt::String_Ref& boot_file)
{
	return _pSMB->Join(target, swarm_size, boot_file);
}

bool DownloadTaskPtr_Compare(const DownloadTaskPtr& a, const DownloadTaskPtr& b)
{
	int v=	((int)a->_TaskInfo.Options.Priority - (int)b->_TaskInfo.Options.Priority) *100000
			- ((int)a->_TaskInfo.Create_TS - (int)b->_TaskInfo.Create_TS);
	return v > 0;
}

bool GreaterSort(TaskInfoPtr a, TaskInfoPtr b) { return (a->Options.Priority > b->Options.Priority); }

void GossipDataPropagation::_OnTick(UINT tick)
{
	if(_WantExit)
		return;

	GDP_AUTO_COUNT(_WorkThreadCT);

	bool bBusy = false;

	{	// Probe Task

		UINT count = 0;
		UINT swarm_id;
		UINT probe_count=0;
		GdpWorkload workload = _DownloadManager.GetWorkload();
		PacketBuf<>buf;

		TaskInfo_Vector tasks;
		_ProbeTasks.Dump(tasks);
		std::sort(tasks.begin(), tasks.end(), GreaterSort);

		for(auto task : tasks)
		{
			if(task->Options.Priority > _PriorityBarForBusyEvent)
				bBusy = true;

			if(_WorkSize && (probe_count + workload.WorkingCount > _WorkSize))
				break;

			if(task->IsNoExpiration()==false && task->Probe_TS && task->CreateElapsed(GDP_PROBE_TASK_TIMEOUT) == true)
			{
				_ProbeTasks.Remove(task->Key);
				continue;
			}

			if(task->ProbeElapsed(GDP_PROBE_TASK_INTERVAL) == false)
				continue;

			task->RefreshProbe();
			probe_count++;

			if(count == 0)
			{
				swarm_id = task->Swarm_Id;
				count = GdpBuildPacketReqBatch(&task->Key, 1, buf);
			}
			else
			{
				if(swarm_id == task->Swarm_Id)
				{
					count = GdpBuildPacketReqBatch_Append(task->Key, buf);
					if(count == 32)
					{
						_BroadcastPacket(buf, swarm_id);
						count = 0;
					}
				}
				else
				{
					_BroadcastPacket(buf, swarm_id);
					swarm_id = task->Swarm_Id;
					count = GdpBuildPacketReqBatch(&task->Key, 1, buf);
				}
			}
		}

		if(count != 0)
			_BroadcastPacket(buf, swarm_id);
	}

	DownloadTaskPtr_Vector tasks;
	_DownloadManager.Dump(tasks);
	std::sort(tasks.begin(), tasks.end(), DownloadTaskPtr_Compare);
	for(auto task : tasks)
	{
		if(task->_TaskInfo.Options.Priority > _PriorityBarForBusyEvent)
			bBusy = true;

		if(task->Timeout() && task->_TaskInfo.IsNoExpiration()==false)
		{
			_DownloadManager.Delete(task->GetKey(), TDR_TIMEOUT);
			GDP_TRACE(
				"Delete Idle Timeout Task: " <<
				" Hash=" << GDP_BIN_TO_BASE16(task->GetKey().Hash)
			);
			
			continue;
		}
		
		// Check if it needs to be downloaded
		if(task->GetManageStatus() == TMS_REJECTED)
		{
			_DownloadManager.Delete(task->GetKey(), TDR_REJECT);
			GDP_TRACE(
				"Delete Rejected Task: " <<
				" Hash=" << GDP_BIN_TO_BASE16(task->GetKey().Hash)
			);
			continue;
		}
		
		
		//check download finished ?
		if(task->Finished())
		{
			os::AtomicIncrement(&Statistics.TaskFinished);

			bool accepted = false;

			if(task->IsCustomizedKey()==false)
			{
				if(task->CheckHash() == true)
				{
					GdpDataInMem* gdim = task->Detach();
					accepted = this->_OnDataRecvAssembled(gdim, task->GetHint());

					ASSERT(accepted); // gdp checked data should be accepted

					GDP_TRACE(
						"#Task# Finished, Hash=" << GDP_BIN_TO_BASE16(task->GetKey().Hash)
						<< ", Hint=" << GDP_BIN_TO_BASE16(task->GetKey().Hint)
						<< ", CheckHash() Succeed"
					);
				}
				else
				{
					GDP_TRACE(
						"#Task# Finished, Hash=" << GDP_BIN_TO_BASE16(task->GetKey().Hash)
						<< ", Hint=" << GDP_BIN_TO_BASE16(task->GetKey().Hint)
						<< ", CheckHash() Failed!"
						);
				}

			}
			else
			{
				
				GdpDataInMem* gdim = task->Detach();
				accepted = this->_OnDataRecvAssembled(gdim, task->GetHint());

				GDP_TRACE(
					"#Task# Finished, Hash=" << GDP_BIN_TO_BASE16(task->GetKey().Hash)
					<< ", Hint=" << GDP_BIN_TO_BASE16(task->GetKey().Hint)
					<< ", It's customized key, will be certified by caller"
					);
			}
			
			_DownloadManager.Delete(task->GetKey(), TDR_FINISH);

			if(accepted == false)
				os::AtomicIncrement(&Statistics.TaskRejected);

			// NoExpiration task will be recreated if not be accepted
			if(task->_TaskInfo.IsNoExpiration() && accepted == false)
			{
				auto& info = task->_TaskInfo;
				this->Request(info.Swarm_Id, &info.Key.Hash, 1, info.Key.Hint, info.Options);
			}

			continue;
		}

		task->OnTick(tick, *this);
	}

	if(tick % 10 == 0)
	{
		bBusy = bBusy || _BroadcastTasks.Count();

		if(_Busy != bBusy)
		{
			_Busy = bBusy;
			CoreEvent(
				MODULE_NETWORK,
				_Busy ? NETWORK_GDP_PRIORITY_BUSY :
				NETWORK_GDP_PRIORITY_IDLE
			);
		}
	}
	
	_DataManager.GC();
}

GossipDataPropagation::~GossipDataPropagation()
{
	_WantExit = true;
	_pCore->SetPacketOnRecvCallBack(NET_PACKET_HEADBYTE_GDP, nullptr, nullptr);
	_pCore->SetOnTickCallback(nullptr, nullptr);

	os::TickCount tc;
	tc.LoadCurrentTick();

	while(_WorkThreadCT.Val() > 0 && tc.TimeLapse()<GDP_EXIT_TIMEOUT)
	{
		os::Sleep(10);
	}
}

int	GossipDataPropagation::BroadcastColdData(UINT swarm_id, GdpDataPage* firstpage, const GdpHash& hash, const GdpHint& hint)
{
	// TBD ....
	_SafeRelease(firstpage);
	return 0;
}

int GossipDataPropagation::Broadcast(UINT swarm_id, LPCBYTE data, UINT len, const GdpHash& hash, const GdpHint& hint, UINT push_count)
{
	PacketBuf<>buf;

	if(data == nullptr) // need to call upper for data
	{
		GdpDataPage* pDataPage = _OnDataRequest(hash, hint, 0);
		if(pDataPage == nullptr)
			return 0;

		data = pDataPage->Data;
		len = pDataPage->DataTotalSize;
	}


	if(len <= GDP_BLOB_NONPAGED_MAXSIZE)
	{
		if(GdpBuildMessageContentPacket(hash, hint, len, 0, len, data, buf))
			_BroadcastPacket(buf, swarm_id, nullptr, PSF_FORWARD_ONLY);
	}
	else
	{
		_RecordBroadcastTask(hash, hint, len);

		UINT count = len / GDP_PACKET_FRAGMENT_SIZE;
		WORD last_piece_size = len % GDP_PACKET_FRAGMENT_SIZE;
		WORD piece_size = GDP_PACKET_FRAGMENT_SIZE;
		UINT offset = 0;
		LPBYTE lpb = (LPBYTE)data;
		if(last_piece_size)
		{
			count++;
		}
		else
		{
			last_piece_size = GDP_PACKET_FRAGMENT_SIZE;
		}

		for(UINT i = 0; i < count; i++)
		{

			if(i == count - 1)
				piece_size = last_piece_size;

			if(GdpBuildMessageContentPacket(hash, hint, len, offset, piece_size, &lpb[offset], buf))
				_BroadcastPacket(buf, swarm_id, nullptr, PSF_FORWARD_ONLY);

			_RecordBroadcastData(hash, hint, offset, piece_size);

			offset += piece_size;

			if(i >= push_count)
				break;
		}
	}

	return 0;
}


int	GossipDataPropagation::Send(LPCBYTE data, UINT len, const GdpHash& hash, const GdpHint& hint, const NetworkAddress& to)
{
	PacketBuf<>buf;

	if(len <= GDP_BLOB_NONPAGED_MAXSIZE)
	{
		if(GdpBuildMessageContentPacket(hash, hint, len, 0, len, data, buf))
			_SendPacket(buf, to);
	}
	else
	{
		int count = len / GDP_PACKET_FRAGMENT_SIZE;
		WORD last_piece_size = len % GDP_PACKET_FRAGMENT_SIZE;
		WORD piece_size = GDP_PACKET_FRAGMENT_SIZE;
		UINT offset = 0;
		LPBYTE lpb = (LPBYTE)data;
		if(last_piece_size)
		{
			count++;
		}
		else
		{
			last_piece_size = GDP_PACKET_FRAGMENT_SIZE;
		}

		for(int i = 0; i < count; i++)
		{

			if(i == count - 1)
				piece_size = last_piece_size;

			if(GdpBuildMessageContentPacket(hash, hint, len, offset, piece_size, &lpb[offset], buf))
				_SendPacket(buf, to);

			offset += piece_size;

			if(i > GDP_AUTO_PUSH_COUNT)
				break;
		}
	}

	return 0;
}


void GossipDataPropagation::RemoveHotData(const GdpHash& hash, const GdpHint& hint)
{
	_DataManager.RemoveData(GdpKey(hash, hint));
}

void GossipDataPropagation::RemoveHotData(const GdpHash& hash)
{
	_DataManager.RemoveData(hash);
}

void GossipDataPropagation::RemoveAllHotData()
{
	_DataManager.RemoveAllData();
}

bool GossipDataPropagation::IsHotDataCached(const GdpHash& hash)
{
	return _DataManager.IsHotDataCached(hash);
}

bool GossipDataPropagation::_ReadData(GdpPieceRecord& record)
{

	if(_DataManager.ReadData(record))
		return true;

	GdpDataPage* pDataPage = _OnDataRequest(*record.Hash, record.Hint, record.Offset / GdpDataPage::DATA_PAGESIZE);

	if(pDataPage == nullptr)
		return false;

	if(_DataManager.SaveDataPage(GdpKey(*record.Hash, record.Hint), pDataPage) == false)
		return false;

	return _DataManager.ReadData(record);
}

void GossipDataPropagation::Request(UINT swarm_id, const GdpHash* hash, UINT hash_count, const GdpHint& hint, const GdpOptions& opt)
{

	UINT count = 0;
	PacketBuf<>buf;
	GdpTaskInfo task_info;
	
	for(UINT i = 0; i < hash_count; i++)
	{
		if(DownloadTaskExist(hash[i], hint))
			continue;

		task_info.Key.Hash = hash[i];
		task_info.Key.Hint = hint;
		task_info.Options  = opt;
		task_info.Swarm_Id = swarm_id;
		
		_ProbeTasks.Add(task_info);
	}
}

void GossipDataPropagation::Leave(UINT swarm_id)
{
	/*
		todo: 
			clean DwonloadTask
			clean GdpDataPage			 
	*/

	_pSMB->Leave(swarm_id);
}

bool GossipDataPropagation::_OnCommand(const os::CommandLine& cmd, rt::String& out)
{
	if(_WantExit)
		return false;

	GDP_AUTO_COUNT(_WorkThreadCT);

	rt::String_Ref op[10];
	rt::String_Ref(cmd.GetText(0)).Split(op, sizeofArray(op), '.');

	if(op[1] == "report")
	{
		return GetStateReport(out);
	}

	if(op[1] == "workload")
	{
		GetWorkload(out);
		return true;
	}

	if(op[1] == "off")
	{
		_GDP_LOG_STATUS_ = GLS_OFF;
		return true;
	}

	if(op[1] == "log" || op[1] == "on")
	{
		_GDP_LOG_STATUS_ = GLS_LOG;
		return true;
	}

	if(op[1] == "trace")
	{
		_GDP_LOG_STATUS_ = GLS_TRACE;
		return true;
	}

	return false;
}

void GossipDataPropagation::GetWorkload(rt::String& out)
{
	auto ret = _DownloadManager.GetWorkload();
	out += (
		J(GDP_TotalCount) = ret.TotalCount,
		J(GDP_TotalBytes) = ret.TotalBytes,
		J(GDP_FinishedCount) = ret.FinishedCount,
		J(GDP_FinishedBytes) = ret.FinishedBytes,
		J(GDP_WorkingCount) = ret.WorkingCount,
		J(GDP_WorkingBytes) = ret.WorkingBytes,
		J(GDP_DropedCount) = ret.DropedCount,
		J(GDP_DropedBytes) = ret.DropedBytes
	);
}

GdpWorkload GossipDataPropagation::GetWorkload()
{
	return _DownloadManager.GetWorkload();
}

bool GossipDataPropagation::GetStateReport(rt::String& out)
{
	static const rt::SS LN("\r\n");
	out += rt::SS("*** Gossip Data Service  ***") + LN;
	
	out += rt::SS("Recv Packet: ") + Statistics.TotalRecvPacket + LN;
	out += rt::SS("Recv Bytes : ") + Statistics.TotalRecvBytes + LN;
	out += rt::SS("Sent Packet: ") + Statistics.TotalSentPacket + LN;
	out += rt::SS("Sent Bytes : ") + Statistics.TotalSentBytes+ LN;
	out += rt::SS("Broadcast Packet: ") + Statistics.TotalBroadcastPacket + LN;
	out += rt::SS("Broadcast Bytes : ") + Statistics.TotalBroadcastBytes + LN;
	out += rt::SS("Invalid Packet: ") + Statistics.TotalInvalidPacket + LN;
	out += rt::SS("Invalid Bytes : ") + Statistics.TotalInvalidBytes + LN;

	out += rt::SS("Task Finished : ") + Statistics.TaskFinished + LN;
	out += rt::SS("Task Rejected : ") + Statistics.TaskRejected + LN;

	out += rt::SS("DataPage Bytes: ") + this->_DataManager.ReportState() + LN;

	return true;
}

bool GossipDataPropagation::_SendPacket(Packet& packet, const NetworkAddress& to, PACKET_SENDING_FLAG flag)
{
	if(_pCore->Send(packet, to, flag))
	{
		os::AtomicIncrement(&Statistics.TotalSentPacket);
		os::AtomicAdd(packet.GetLength(), &Statistics.TotalSentBytes);

		return true;
	}
	
	return false;
}

int	GossipDataPropagation::_BroadcastPacket(Packet& packet, UINT swarm_id, const NetworkAddress* skip, PACKET_SENDING_FLAG flag)
{
	os::AtomicIncrement(&Statistics.TotalBroadcastPacket);
	os::AtomicAdd(packet.GetLength(), &Statistics.TotalBroadcastBytes);

	return _pCore->SMB().Broadcast(packet, swarm_id, skip, flag);
}

void GossipDataPropagation::EnableCommand()
{
	if(_pCore->HasAPI())
		_pCore->API().SetCommandExtension("gdp", this, &GossipDataPropagation::_OnCommand);
}

void GossipDataPropagation::_RecordRecvInvalidData(LPCVOID pData, UINT len)
{
	os::AtomicIncrement(&Statistics.TotalInvalidPacket);
	os::AtomicAdd(len, &Statistics.TotalInvalidBytes);
}

void GossipDataPropagation::_RecordBroadcastData(const GdpHash& hash, const GdpHint& hint, const UINT offset, const UINT length)
{
	_BroadcastTasks.Record(hash, hint, offset, length);
}

void GossipDataPropagation::_RecordBroadcastTask(const GdpHash& hash, const GdpHint& hint, const UINT size)
{
	_BroadcastTasks.Add(hash, hint, size);
}

} // namespace upw

