#include "gdp.h"
#include "gdp_task.h"
#include "gdp_message.h"


namespace upw
{

const BYTE BITMASK[8] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
#define GDP_PIECE_INDEX_FROM_OFFSET(n) (int)(n / GDP_PACKET_FRAGMENT_SIZE)

void GDP_ResourceBitmap::Init(int BytesLength)
{
	ASSERT(_pRoom == nullptr);
	ASSERT(BytesLength <= GDP_BLOB_MAXSIZE);

	_BytesLength = BytesLength;

	_LastPieceBytesLength = (_BytesLength % PIECE_SIZE);
	if(_LastPieceBytesLength == 0)
		_LastPieceBytesLength = PIECE_SIZE;

	_BitsLength = (_BytesLength / PIECE_SIZE);
	if(_BytesLength % PIECE_SIZE)
		_BitsLength++;
	
	_RoomLength = (_BitsLength / ROOM_SIZE);
	if(_BitsLength % ROOM_SIZE)
		_RoomLength++;
		
	_pRoom = (LPDWORD) GDP_MALLOC(_RoomLength * ROOM_SIZE / 8);

	GDP_MEMSET(_pRoom, 0, _RoomLength * ROOM_SIZE / 8);
}

GDP_ResourceBitmap::~GDP_ResourceBitmap()
{
	if(_pRoom)
	{
		GDP_FREE(_pRoom);
	}
}

bool GDP_ResourceBitmap::SetBit(int index)
{
	ASSERT(_pRoom);
	ASSERT(0 <= index && index < _BitsLength);
	if((index < 0 || index >= _BitsLength))
	{
		// todo: alert
		return false;
	}

	int i = index / ROOM_SIZE;
	int ii = index % ROOM_SIZE;
	DWORD mask = (DWORD)1 << ii;
	DWORD r = os::AtomicOr(mask, &_pRoom[i]);

	if((r & mask) == 0)
	{
		_BitsCounter++;

		if(index == _BitsLength - 1)
			_BytesCounter += _LastPieceBytesLength;
		else
			_BytesCounter += PIECE_SIZE;

		return true;
	}
	else
		return false;
}

bool GDP_ResourceBitmap::GetBit(int index)
{
	ASSERT(_pRoom);

	if((index < 0 || index >= _BitsLength))
	{
		// todo: alert
		return false;
	}

	int i = index / ROOM_SIZE;
	int ii = index % ROOM_SIZE;
	DWORD mask = (DWORD)1 << ii;
	return _pRoom[i] & mask;
}

bool GDP_ResourceBitmap::IsFull()
{
	ASSERT(_pRoom);
	return _BitsCounter == _BitsLength;
}


void GdpDownloadTask::AddPeer(const NetworkAddress& na)
{
	EnterCSBlock(_TaskLock);

	ResourcePeer* lpPeer = _FindPeerByAddress(na);

	if(lpPeer)
		return;

	lpPeer = _FindIdlePeerSlot();
	if(lpPeer)
	{
		lpPeer->Start(na);
		_WorkingPeersCount++;
	}
	else
	{
		// no slot
	}

}

ResourcePeer* GdpDownloadTask::_FindPeerByAddress(const NetworkAddress& na)
{
	EnterCSBlock(_TaskLock);
	for(int i = 0; i < GDP_TASK_MAX_PEERS; i++)
	{
		auto& peer = _WorkingPeers[i];

		if(peer.timestamp!=0 && peer.addr == na)	
			return &_WorkingPeers[i];
	}
	return nullptr;
}


void GdpDownloadTask::SetDataPiece(int offset, LPBYTE pData, int length)
{
	EnterCSBlock(_TaskLock);

	if(_Bitmap.GetBit(offset / GDP_PACKET_FRAGMENT_SIZE))
		return;

	GDP_MEMCPY(&GetData()[offset], pData, length);
	
	_Bitmap.SetBit(offset / GDP_PACKET_FRAGMENT_SIZE);

	_Downloaded += length;
}

bool GdpDownloadTask::Finished()
{
	return _Downloaded >= _DataLen;
	//EnterCSBlock(_TaskLock);
	//return _Bitmap.GetFullState();
}

bool GdpDownloadTask::CheckHash()
{
	EnterCSBlock(_TaskLock);

	GdpHash datahash;
	datahash.Hash(GetData(), GetLength());

	return (_TaskInfo.Key.Hash == datahash);
}

bool GdpDownloadTask::Initialize(UINT prefix_size, UINT suffix_size, INT idle_timeout)
{ 
	EnterCSBlock(_TaskLock); 
	_IdleTimeout = idle_timeout;  
	
	if( _Helper.Initialize(_TaskInfo.Key.Hash, _Type, prefix_size, _DataLen, suffix_size) == false)
		return false;
	
	for(int i = 0; i < GDP_AUTO_PUSH_COUNT; i++)
	{
		if(_AutoPushFlag[i] == true)
			SetDataPiece(i* GDP_PACKET_FRAGMENT_SIZE, &_AutoPushBuffer[i* GDP_PACKET_FRAGMENT_SIZE],GDP_PACKET_FRAGMENT_SIZE);
	}

	return true;
}


bool GdpDownloadTask::OnData(int offset, LPBYTE pData, int length, const NetworkAddress& from)
{
	EnterCSBlock(_TaskLock);

	if(Finished())
		return true;

	AddPeer(from);

	_LatestRecvTS = os::TickCount::Get();


	if(this->Valid() == false)
	{
		int i = offset / GDP_PACKET_FRAGMENT_SIZE;
		int m = offset % GDP_PACKET_FRAGMENT_SIZE;
		if(i< GDP_AUTO_PUSH_COUNT && m == 0 && length == GDP_PACKET_FRAGMENT_SIZE)
		{
			_AutoPushFlag[i] = true;
			GDP_MEMCPY(&_AutoPushBuffer[offset], pData, length);
		}
		return false;
	}

	GDP_TRACE("OnData:" << offset << "	Len:" << length);

	if(offset == 0 && length == 4)
	{
		ResourcePeer* lpPeer = _FindPeerByAddress(from);
		if(lpPeer)
		{
			UINT* tm = (UINT*)pData;
			if(*tm>lpPeer->lastest_finished_request)
				lpPeer->lastest_finished_request = *tm;
		}
		return true;
	}

	if(offset + length > GetLength())
		return false;

	SetDataPiece(offset, pData, length);

	/*
		Is this piece_index in requests?
			y: one request finished on schedule
			n:
				1. broadcast auto send pieces (GDP_AUTO_PUSH_COUNT)
				2. receive after timeout, but it has been removed from request
	*/
	auto it = _Requests.find(GDP_PIECE_INDEX_FROM_OFFSET(offset));
	if(it != _Requests.end() && it->second.addr == from)
	{
		ResourcePeer* lpPeer = _FindPeerByAddress(from);
		if(lpPeer)
		{
			if(lpPeer->used>0)
				lpPeer->used--;

			int rt = os::TickCount::Get() - it->second.timestamp;

			if(it->second.timestamp > lpPeer->lastest_finished_request)
				lpPeer->lastest_finished_request = it->second.timestamp;
			

			if(rt < lpPeer->min_rt) lpPeer->min_rt = rt;
			if(rt > lpPeer->max_rt) lpPeer->max_rt = rt;

			if(rt < lpPeer->this_tick_min_rt) lpPeer->this_tick_min_rt = rt;
			if(rt > lpPeer->this_tick_max_rt) lpPeer->this_tick_max_rt = rt;


			lpPeer->this_tick_finished++;

			GDP_TRACE("RT: " << rt << "  this_tick_finished: "<< lpPeer->this_tick_finished);
		}
	}


	if(it != _Requests.end())
		_Requests.erase(it);
	

	bool rt = Finished();
	if(rt)
	{
		GDP_TRACE("Data Transfer Finished [" << GDP_BIN_TO_BASE16(_TaskInfo.Key.Hash)<<"], used time:"<<(os::TickCount::Get() - _StartTS));
	}
	return rt;
}

void GdpDownloadTask::OnTick(UINT tick, GossipDataPropagation& gossip_data_svc)
{
	EnterCSBlock(_TaskLock);

	UINT tick_start_ts = os::TickCount::Get();

	GDP_TRACE("============================================");
	GDP_TRACE("key  :" << GDP_BIN_TO_BASE16(_TaskInfo.Key.Hash));
	GDP_TRACE("start:" << tick_start_ts);
	GDP_TRACE("request count:" << _Requests.size());

	if(_Requests.size() == 0)
	{
		for(int i = 0; i < GDP_TASK_MAX_PEERS; i++)
			if(_WorkingPeers[i].InUse())
			{

				ResourcePeer* lpPeer = &_WorkingPeers[i];
				lpPeer->used = 0;
			}
	}

	int pull_ct = 0;
	int tmot_ct = 0;
	PacketBuf<>buf;
	

	// traversing requests, find timeout pieces
	for(auto it = _Requests.begin(); it != _Requests.end();)
	{
		ResourcePeer* lpPeer = _FindPeerByAddress(it->second.addr);

		if(lpPeer == nullptr) // only deal with timeout request
		{
			if(it->second.timestamp.TimeLapse() > 2000)
			{
				tmot_ct++;
				_Requests.erase(it++);
			}
			else
			{
				it++;
			}
			continue;
		}

		if(it->second.timestamp.TimeLapse() > 2000 ||
			it->second.timestamp.TimeLapse(lpPeer->lastest_finished_request) > 200 ) // timeout
		{
			tmot_ct++;

			if(lpPeer)
			{
				if(lpPeer->used>0)
					lpPeer->used--;
				

				lpPeer->this_tick_timeout++; // cumulate timeout count

				if(lpPeer->first_timeout == 0)
					lpPeer->first_timeout = os::TickCount::Get();

			}
			_Requests.erase(it++);

		}
		else
			it++;
	}

	GDP_TRACE("timeout count:" << tmot_ct);

	// traversing peers, recalculate their quota
	int peer[GDP_TASK_MAX_PEERS];
	int peer_count = 0;

	for(int i = 0; i < GDP_TASK_MAX_PEERS; i++)
		if(_WorkingPeers[i].InUse())
		{

			ResourcePeer* lpPeer = &_WorkingPeers[i];

			if(lpPeer->this_tick_finished > 0 && lpPeer->this_tick_timeout<4)
			{
				/*
				if(lpPeer->first_timeout == 0)
				{
					lpPeer->quota += lpPeer->this_tick_finished;
				}
				else
				{
					lpPeer->quota += 1;
					if(lpPeer->best - lpPeer->quota > 0)
						lpPeer->quota += (lpPeer->this_tick_finished / 4);

				}
				*/
				lpPeer->quota += lpPeer->this_tick_finished;

				int rts = lpPeer->this_tick_min_rt + lpPeer->this_tick_max_rt;
				
				if(rts < 4)
					lpPeer->quota += 1024;
				else if(rts < 8)
					lpPeer->quota += 512;
				else if(rts < 64)
					lpPeer->quota += 256;
				else if(rts < 128)
					lpPeer->quota += 128;
				
				
			}
			
			if(lpPeer->this_tick_timeout > 0)
			{
				lpPeer->quota -= lpPeer->this_tick_timeout;
				if(lpPeer->quota < 1)
					lpPeer->quota = 1;
			}

			if(lpPeer->quota > lpPeer->best)
				lpPeer->best = lpPeer->quota;

			GDP_TRACE(	"   Index:" << i <<
						"   Addr:" << lpPeer->addr_string <<
						"   BEST:" << lpPeer->best << 
						"	QUOTA:" << lpPeer->quota << 
						"   USED:" << lpPeer->used <<
						"   MinRT:" << lpPeer->this_tick_min_rt<<
						"   MaxRT:" << lpPeer->this_tick_max_rt
				);

			lpPeer->this_tick_quota = lpPeer->quota;

			/*
			if(lpPeer->quota > 4)
				lpPeer->this_tick_quota = lpPeer->quota / 2;
			*/
			
					

			// reset timeout count
			{
				lpPeer->this_tick_used= 0;
				lpPeer->this_tick_timeout = 0;
				lpPeer->this_tick_finished = 0;
				lpPeer->this_tick_min_rt = 10000;
				lpPeer->this_tick_max_rt = 0;
			}


			//check if there are unused quota
			if(_WorkingPeers[i].used < _WorkingPeers[i].quota)
				peer[peer_count++] = i;
		}

	if(peer_count == 0)
	{
		//ASSERT(_Requests.size());
		GDP_TRACE("No usable peer!");
		return;
	}
		

	int peer_index = 0;
	ResourcePeer* WorkPeer = &_WorkingPeers[peer[peer_index]];

	if(this->Valid()==false)
	{
		if(_Requests.count(0) == 0)
		{
			_Requests[0] = GDP_PieceTask(0, WorkPeer->addr);

			buf.Reset();
			if(GdpBuildMessagePullPacketWithHint(_TaskInfo.Key.Hash, _TaskInfo.Key.Hint, 0, GDP_PACKET_FRAGMENT_SIZE, buf))
				gossip_data_svc._SendPacket(buf, WorkPeer->addr);

			GDP_TRACE("try to get first piece!");
		}
		
		GDP_TRACE("task need first piece to start");
		return;
	}

	//int count = 0;
	int len = _Bitmap.GetBitsLength();
	int last_piece_len = this->GetLength() % GDP_PACKET_FRAGMENT_SIZE;

	if(last_piece_len == 0)
		last_piece_len = GDP_PACKET_FRAGMENT_SIZE;

	//int thistime = 0;

	int req_offset = 0;
	int req_len = 0;

	int from = os::TickCount::Get() - _StartTS > 200 ? 0 : GDP_AUTO_PUSH_COUNT;

	// when the request data range is continuous, try to merge them into one request

	for(int i = from; i < len; i++)
	{

		if(_Bitmap.GetBit(i) == false && _Requests.count(i) == 0)
		{

			_Requests[i] = GDP_PieceTask(i, WorkPeer->addr);

			// no more continuous, send request
			if( (i * GDP_PACKET_FRAGMENT_SIZE != req_offset+req_len && req_len != 0) || 
				 (req_len>=1024*63) )
			{
				if(GdpBuildMessagePullPacketWithHint(_TaskInfo.Key.Hash, _TaskInfo.Key.Hint, req_offset, req_len, buf))
					gossip_data_svc._SendPacket(buf, WorkPeer->addr);

				GDP_TRACE("Request offset:" << req_offset << "	Len:" << req_len);
				
				req_offset = 0;
				req_len = 0;
			}


			if(req_len == 0) // a new request
			{
				req_offset = i * GDP_PACKET_FRAGMENT_SIZE;
			}

			req_len += (i == len - 1 ? last_piece_len : GDP_PACKET_FRAGMENT_SIZE);

			pull_ct++;
			WorkPeer->used++;

			WorkPeer->this_tick_used++;

			if(WorkPeer->used >= WorkPeer->quota || WorkPeer->this_tick_used >=WorkPeer->this_tick_quota )
			{

				if(req_len != 0) // before change peer, send request
				{
					if(GdpBuildMessagePullPacketWithHint(_TaskInfo.Key.Hash, _TaskInfo.Key.Hint, req_offset, req_len, buf))
						gossip_data_svc._SendPacket(buf, WorkPeer->addr);

					GDP_TRACE("Request offset:" << req_offset << "	Len:" << req_len);
					

					req_offset = 0;
					req_len = 0;
				}


				peer_index++;
				if(peer_index >= peer_count)
					break;
				WorkPeer = &_WorkingPeers[peer[peer_index]];
			}


		}
	}


	if(req_len != 0) // maybe request exists 
	{
		if(GdpBuildMessagePullPacketWithHint(_TaskInfo.Key.Hash, _TaskInfo.Key.Hint, req_offset, req_len, buf))
			gossip_data_svc._SendPacket(buf, WorkPeer->addr);

		GDP_TRACE("Request offset:" << req_offset << "	Len:" << req_len);
		
		req_offset = 0;
		req_len = 0;
	}

	if(this->Valid())
	{
		GDP_TRACE("send heartbeat");
		for(int i = 0; i < GDP_TASK_MAX_PEERS; i++)
			if(_WorkingPeers[i].InUse())
			{
				ResourcePeer* lpPeer = &_WorkingPeers[i];
				if(lpPeer->this_tick_used > 0)
				{
					//Heartbeat
					buf.Reset();
					if(GdpBuildMessagePullPacketWithHint(_TaskInfo.Key.Hash, _TaskInfo.Key.Hint, 0, 4, (LPCBYTE)&tick_start_ts, sizeof(tick_start_ts), buf))
						gossip_data_svc._SendPacket(buf, lpPeer->addr);
				}
			}
	}
	
	
	GDP_TRACE("Pull:" << pull_ct);
	GDP_TRACE("============================================");
	
}

ResourcePeer* GdpDownloadTask::_FindIdlePeerSlot()
{
	EnterCSBlock(_TaskLock);
	for(int i = 0; i < GDP_TASK_MAX_PEERS; i++)
		if(_WorkingPeers[i].InUse() == false)
		{
			return &_WorkingPeers[i];
		}
	return nullptr;
}

void GdpDownloadTask::GetDownloadStatus(GdpDownloadTaskStatus& status)
{
	EnterCSBlock(_TaskLock);
	status.DataLen = _DataLen;
	status.Downloaded = _Downloaded;

}

void GdpDownloadTask::Execute(GdpPacketContext& context)
{

}

GdpDownloadTask::GdpDownloadTask(const GdpKey& key, UINT Length, GdpTaskInfo* task_info)
{
	rt::Zero(_TaskInfo);

	_TaskInfo.Key = key;

	if(task_info)
		_TaskInfo= *task_info;

	_DataLen = Length;
	
	_Bitmap.Init(_DataLen);
	_StartTS = os::TickCount::Get();
	_LatestRecvTS = _StartTS;
	_IdleTimeout = GDP_TASK_MAX_IDLE;

	GDP_LOG(
		"GdpDownloadTask::GdpDownloadTask(), Hash=" << GDP_BIN_TO_BASE16(key.Hash)
		<< ", Hint=" << GDP_BIN_TO_BASE16(key.Hint)
	);
}

GdpDownloadTask::~GdpDownloadTask()
{
	GDP_LOG(
		"GdpDownloadTask::~GdpDownloadTask(), Hash=" << GDP_BIN_TO_BASE16(_TaskInfo.Key.Hash)
		<< ", Hint=" << GDP_BIN_TO_BASE16(_TaskInfo.Key.Hint)
	);
}

bool GdpDownloadTaskManager::Find(const GdpKey& key, DownloadTaskPtr& dst)
{
	EnterCSBlock(_TasksCS);

	auto it = _Tasks.find(key);
	if(it == _Tasks.end())
		return false;

	dst = it->second;
	return true;
}

bool GdpDownloadTaskManager::Add(const GdpKey& key, UINT len, GdpTaskInfo* task_info, DownloadTaskPtr& dst)
{
	EnterCSBlock(_TasksCS);

	if(_Tasks.count(key))
	{
		dst = _Tasks[key];
		return false;
	}

	GDP_TRACE("Create DownloadTask: " << GDP_BIN_TO_BASE16(key.Hash));

	if(_TotalHash.count(key) == 0)
	{
		_TotalHash.insert(key);
		_TotalCount++;
		_TotalBytes += len;
	}
	
	DownloadTaskPtr lpTask;
	Alloc_DownloadTask(key, len, task_info, lpTask);
	
	
	_Tasks[key] = lpTask;
	dst = lpTask;
	return true;
}

bool GdpDownloadTaskManager::Dump(DownloadTaskPtr_Vector& dst)
{
	EnterCSBlock(_TasksCS);

	_WorkingBytes = 0;
	dst.resize(_Tasks.size());
	int i = 0;
	for(auto& kv : _Tasks)
	{
		dst[i++] = kv.second;
		_WorkingBytes += kv.second->GetDownloadSize();
	}

	_WorkingCount = i;

	return true;
}

bool GdpDownloadTaskManager::Delete(const GdpKey& key, TASK_DELETE_REASON reason)
{
	EnterCSBlock(_TasksCS);

	DownloadTaskPtr pTask;

	if(!Find(key, pTask)) return false;

	switch (reason) 
	{
	case TDR_FINISH:
		if(_FinishedHash.count(key) == 0)
		{
			_FinishedHash.insert(key);
			_FinishedCount++;
			_FinishedBytes += pTask->GetLength();
		}
		break;

	case TDR_TIMEOUT:
		if(_DropedHash.count(key) == 0)
		{
			_DropedHash.insert(key);
			_DropedCount++;
			_DropedBytes += pTask->GetLength();
		}
		break;

	case TDR_REJECT:
		// tbd
		break;

	case TDR_USER:
		// tbd
		break;

	default:
		ASSERT(0);
	}
		


	return _Tasks.erase(key) !=0 ;
}

GdpWorkload GdpDownloadTaskManager::GetWorkload()
{
	GdpWorkload ret;

	ret.TotalCount = _TotalCount;
	ret.TotalBytes = _TotalBytes;
	ret.FinishedCount = _FinishedCount;
	ret.FinishedBytes = _FinishedBytes;
	ret.WorkingCount = _WorkingCount;
	ret.WorkingBytes = _WorkingBytes;
	ret.DropedCount = _DropedCount;
	ret.DropedBytes = _DropedBytes;

	return ret;
}

bool GdpDownloadTaskManager::Query(const GdpKey& key, GdpDownloadTaskStatus& status)
{
	EnterCSBlock(_TasksCS);

	DownloadTaskPtr pTask;
	
	if( Find(key, pTask) )
	{
		pTask->GetDownloadStatus(status);
		return true;
	}
	else
	{
		return false;
	}
	
}

bool GdpDownloadTaskManager::Exist(const GdpKey& key)
{
	EnterCSBlock(_TasksCS);

	auto it = _Tasks.find(key);
	return it != _Tasks.end();
}

void GdpProbeTasks::Dump(TaskInfo_Vector& dst)
{
	EnterCSBlock(_TasksCS);

	dst.resize(_Tasks.size());
	int i = 0;
	for(auto& kv : _Tasks)
	{
		dst[i++] = kv.second;
	}

}



bool GdpProbeTasks::Exist(const GdpKey& key)
{
	EnterCSBlock(_TasksCS);
	auto it = _Tasks.find(key);
	return it != _Tasks.end();
}

bool GdpProbeTasks::Add(const GdpTaskInfo& info)
{
	EnterCSBlock(_TasksCS);

	auto it = _Tasks.find(info.Key);
	if(it != _Tasks.end())
	{
		auto p = it->second;
		if(info.Options.Priority > p->Options.Priority)
			p->Options.Priority = info.Options.Priority;
		return false;
	}

	auto p = std::make_shared<GdpTaskInfo>();
	*p = info;
	_Tasks[info.Key] = p;
	return true;
}

TaskInfoPtr	GdpProbeTasks::RemoveAndGetPtr(const GdpKey& key)
{
	EnterCSBlock(_TasksCS);
	
	auto it = _Tasks.find(key);

	if(it == _Tasks.end())
		return nullptr;

	auto r = it->second;
	_Tasks.erase(it);
	return r;
}


bool GdpProbeTasks::Remove(const GdpKey& key)
{
	EnterCSBlock(_TasksCS);
	return _Tasks.erase(key)>0;
}


bool GDP_PotentialTasks::AddPieceData(const GdpKey& key, UINT offset, WORD length, LPCVOID lpData, UINT size)
{
	PotentialTask* pTask;

	auto it = Tasks.find(key);

	if(it == Tasks.end())
	{
		pTask = new PotentialTask();
		Tasks[key] = pTask;
	}
	else
	{
		pTask = it->second;
		if(pTask->Pieces.find(offset) != pTask->Pieces.end())
			return false;
	}

	PotentialPiece* pPiece = new PotentialPiece;

	pPiece->offset = offset;
	pPiece->length = length;
	pPiece->data = rt::String_Ref((char*)lpData, size);
	pTask->Pieces[offset] = pPiece;

	return true;
}

bool GdpBroadcastTasks::Add(const GdpHash& hash, const GdpHint& hint, const UINT size)
{
	EnterCSBlock(_TasksCS);
	GdpKey key(hash, hint);
	if(_Tasks.count(key))	return false;

	auto info = std::make_shared<GDP_Broadcast_Info>(key, size);
	_Tasks[key] = info;
	return true;
}

bool GdpBroadcastTasks::Record(const GdpHash& hash, const GdpHint& hint, const UINT offset, const UINT length)
{
	EnterCSBlock(_TasksCS);
	GdpKey key(hash, hint);

	auto it = _Tasks.find(key);
	if(it == _Tasks.end())
		return false;

	BroadcastInfoPtr task = it->second;
	bool ret = task->Update(offset / GDP_PACKET_FRAGMENT_SIZE);

	if(task->SendMap.IsFull())
		_Tasks.erase(it);

	return ret;
}

void GdpBroadcastTasks::CleanTimeout(const uint64_t timeout_ms)
{
	EnterCSBlock(_TasksCS);
	uint64_t now = os::TickCount::Get();
	auto it = _Tasks.begin();
	while(it!=_Tasks.end())
	{
		if(it->second->UpdateTime + timeout_ms < now)
			_Tasks.erase(it++);
		else
			it++;
	}
}

size_t GdpBroadcastTasks::Count()
{
	EnterCSBlock(_TasksCS);
	CleanTimeout(GDP_BROADCAST_TASK_TIMEOUT);
	return _Tasks.size();
}


}
