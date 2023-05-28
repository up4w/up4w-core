#pragma once

#include "gdp_base.h"
#include "gdp_peer.h"


namespace upw
{

class GDP_ResourceBitmap				
{	
	static	const int PIECE_SIZE	= GDP_PACKET_FRAGMENT_SIZE;	// normal 1024
	static	const int ROOM_SIZE		= 32;						// use one DWORD to store 32 bits
private:
	int		_BytesLength	= 0;			// data length in bytes
	int		_BitsLength		= 0;			// equal (_BytesLength / PIECE_SIZE) + (_BytesLength % PIECE_SIZE ? 1:0)
	int		_RoomLength		= 0;			// equal (_BitsLength / ROOM_SIZE) + (_BitsLength % ROOM_SIZE ? 1:0)
	LPDWORD	_pRoom			= nullptr;

	int		_LastPieceBytesLength = 0;		

	int		_BytesCounter	= 0;
	int		_BitsCounter	= 0;

public:
	UINT	GetBytesLength() { return _BytesLength; }
	UINT	GetBitsLength() { return _BitsLength; }

	void	Init(int data_bytes_length);	// only one time
	bool	SetBit(int index);				// only set bit to 1, return false when the bit had been set
	bool	GetBit(int index);				// return true when the bit had been set
	bool	IsFull();						// return true when all bits had been set

	GDP_ResourceBitmap(int datasize) { Init(datasize); }
	GDP_ResourceBitmap() { /*EMPTY*/; }
	~GDP_ResourceBitmap();
};

struct GDP_PieceTask
{
	int				index = 0;
	os::TickCount	timestamp = 0;
	NetworkAddress	addr;

	GDP_PieceTask() {}
	GDP_PieceTask(UINT index, const NetworkAddress& addr) : index(index), addr(addr) { Start(); }
	inline bool		InUse() { return timestamp; }
	inline void		Start() { timestamp.LoadCurrentTick(); }
	inline void		Stop() { timestamp = 0; }
};

using Index_PieceTask_Map	= rt::hash_map<UINT, GDP_PieceTask>;


enum TASK_MANAGE_STATUS{
	TMS_NONE = 0,
	TMS_ACCEPTED,
	TMS_REJECTED
};

enum TASK_DELETE_REASON {
	TDR_FINISH = 0,
	TDR_TIMEOUT,
	TDR_REJECT,
	TDR_USER
};


class GossipDataPropagation;


struct GDP_CommonTask
{
	GdpHint				_Hint;
	GdpHash				_Hash;
};



class GdpDownloadTask
{
	GdpDataInMemHelper	_Helper;		// details in GdpDataInMem
	INT						_Type;
	UINT					_DataLen;
	UINT					_Downloaded = 0;

	bool					_AutoPushFlag[GDP_AUTO_PUSH_COUNT] = { false };
	BYTE					_AutoPushBuffer[GDP_AUTO_PUSH_COUNT* GDP_PACKET_FRAGMENT_SIZE];

	//GdpHint				_Hint;
	GDP_ResourceBitmap		_Bitmap;		// data available bitmap

	UINT					_StartTS;		// start timestamp
	UINT					_LatestRecvTS;	// lastest recv data timestamp
	INT						_IdleTimeout;   
	TASK_MANAGE_STATUS		_TMS = TMS_NONE;

	int						_WorkingPeersCount = 0;
	ResourcePeer			_WorkingPeers[GDP_TASK_MAX_PEERS];
	ResourcePeer*			_FindIdlePeerSlot();
	ResourcePeer*			_FindPeerByAddress(const NetworkAddress& na);

	Index_PieceTask_Map		_Requests;		// Piece Index --> GDP_PieceTask

	os::CriticalSection		_TaskLock;

	

public:

	GdpTaskInfo			_TaskInfo;

	LPBYTE				GetData() { return _Helper.GetData(); }
	int					GetLength() { return _DataLen; }
	//GdpHash*			GetHash() { return &_Hash; }
	const GdpKey&		GetKey() { return _TaskInfo.Key; }
	bool				IsCustomizedKey() { return _TaskInfo.IsCustomizedKey(); }

	GdpDataInMem*		Detach() { return _Helper.Detach(); }
	GdpDataInMem*		GetDataInMem() { return _Helper.GetDataInMem(); }

	TASK_MANAGE_STATUS	GetManageStatus() { return _TMS; }
	void				SetManageStatus(TASK_MANAGE_STATUS st) { _TMS = st; }
	bool				Timeout() { return (INT) os::TickCount::Get() - (INT)_LatestRecvTS > _IdleTimeout; }

	void				SetHint(const GdpHint& hint) { ASSERT(0); _TaskInfo.Key.Hint = hint; }
	const GdpHint&		GetHint() { return _TaskInfo.Key.Hint; }

	bool	Initialize(UINT prefix_size, UINT suffix_size, INT idle_timeout);
	void	AddPeer(const NetworkAddress& na);
	void	SetDataPiece(int offset, LPBYTE pData, int length);
	bool	Finished();
	bool	Valid() { return _Helper.GetInitialized();};
	void	OnTick(UINT tick, GossipDataPropagation& gossip_data_svc);
	bool	OnData(int offset, LPBYTE pData, int length, const NetworkAddress& from);
	bool	CheckHash();
	void	GetDownloadStatus(GdpDownloadTaskStatus& status);
	UINT	GetDownloadSize() { return _Downloaded; }

	void	Execute(GdpPacketContext& context);

	GdpDownloadTask(const GdpKey& key, UINT Length, GdpTaskInfo* task_info);
	~GdpDownloadTask();
};

using DownloadTaskPtr				= std::shared_ptr<GdpDownloadTask>;
using DataHash_DownloadTaskPtr_Map	= rt::hash_map<GdpKey, DownloadTaskPtr, rt::_details::hash_compare_fix<GdpKey>>;
using DownloadTaskPtr_Vector		= std::vector<DownloadTaskPtr>;

inline bool	Alloc_DownloadTask(const GdpKey& key, UINT len, GdpTaskInfo* task_info, DownloadTaskPtr& dst)
{	dst = std::make_shared<GdpDownloadTask>(key, len, task_info);
	return true;
}

class GdpDownloadTaskManager
{
	DataHash_DownloadTaskPtr_Map	_Tasks;
	os::CriticalSection				_TasksCS;

	rt::hash_set <GdpKey, rt::_details::hash_compare_fix<GdpKey>>		_TotalHash;
	rt::hash_set <GdpKey, rt::_details::hash_compare_fix<GdpKey>>		_FinishedHash;
	rt::hash_set <GdpKey, rt::_details::hash_compare_fix<GdpKey>>		_DropedHash;
	
	int64_t	_TotalCount = 0;
	int64_t	_TotalBytes = 0;
	int64_t _FinishedCount = 0;
	int64_t _FinishedBytes = 0;
	int64_t _DropedCount = 0;
	int64_t _DropedBytes = 0;
	int64_t _WorkingCount = 0;
	int64_t _WorkingBytes = 0;
public:
	bool	Find(const GdpKey& key, DownloadTaskPtr& dst);
	bool	Add(const GdpKey& key, UINT len, GdpTaskInfo* task_info, DownloadTaskPtr& dst);
	bool	Dump(DownloadTaskPtr_Vector& dst);
	bool	Delete(const GdpKey& key, TASK_DELETE_REASON reason);
	bool	Query(const GdpKey& key, GdpDownloadTaskStatus& status);
	bool	Exist(const GdpKey& key);

	GdpWorkload	GetWorkload();
};


class GdpProbeTasks	// used in: Request() by upper, _OnTick() by netcore, _OnRecv_MessageContent by netcore
{
	Key_TaskInfoPtr_Map _Tasks;
	os::CriticalSection	_TasksCS;
public:
	bool	Add(const GdpTaskInfo& info);
	TaskInfoPtr	RemoveAndGetPtr(const GdpKey& key);
	bool	Remove(const GdpKey& key);
	bool	Exist(const GdpKey& key);
	void	Dump(TaskInfo_Vector& dst);
};


struct PotentialPiece
{
	UINT offset;
	WORD length;
	rt::String data;
};

class PotentialTask
{
public:
	rt::hash_map<UINT, PotentialPiece*> Pieces;
};

class GDP_PotentialTasks	//not thread safe, only be used in GdpDownloadTaskManager, be careful!
{
public:
	rt::hash_map<GdpKey, PotentialTask*, rt::_details::hash_compare_fix<GdpKey>> Tasks;
	bool AddPieceData(const GdpKey& key, UINT offset, WORD length, LPCVOID lpData, UINT size);

};


class GdpBroadcastTasks	// 
{
	struct GDP_Broadcast_Info
	{
		GdpKey				Key;
		uint64_t			CreateTime = 0;
		uint64_t			UpdateTime = 0;
		GDP_ResourceBitmap	SendMap;

		GDP_Broadcast_Info(const GdpKey& key, const UINT size) : Key(key) {
			SendMap.Init(size);
			UpdateTime = CreateTime = os::TickCount::Get();
		}
		bool Update(const UINT index) {
			UpdateTime = os::TickCount::Get();
			return SendMap.SetBit(index);
		}
	};
	using BroadcastInfoPtr = std::shared_ptr<GDP_Broadcast_Info>;
	using Key_BroadcastInfoPtr_Map = rt::hash_map<GdpKey, BroadcastInfoPtr, rt::_details::hash_compare_fix<GdpKey>>;

	Key_BroadcastInfoPtr_Map	_Tasks;
	os::CriticalSection			_TasksCS;
public:
	bool	Add(const GdpHash& hash, const GdpHint& hint, const UINT size);
	bool	Record(const GdpHash& hash, const GdpHint& hint, const UINT offset, const UINT length);
	void	CleanTimeout(const uint64_t timeout_ms);
	size_t	Count();
};




}