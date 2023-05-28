#pragma once
#include "../../externs/miniposix/core/ext/botan/botan.h"
#include "../net_types.h"
#include "../gdp/gdp_base.h"
#include "mrc_swarm.h"
#include "mrc_controls.h"


namespace upw
{

struct MrcMessage;
struct MrcEnvelope;
struct MrcDagStatus;
struct MrcMediaOffloadItem;
class MessageRelayCore;
class MrcMediaRelayCore;
class MrcFragmentAssembler;
class MrcMessageAssembler;

class MrcExtMessageRelaySwarms
{
	typedef std::shared_ptr<MrcMessageRelaySwarm> MrcSwarmRelayPtr;
protected:
	os::CriticalSection	_CS;

	rt::hash_map<DhtAddress, MrcSwarmRelayPtr> _MrcSwarmRelayMap;
	rt::hash_map<MrcContactPointNum, MrcSwarmRelayPtr> _CPID_Map;

	NetworkServiceCore*		_pNetCore = nullptr;
	itfc::StorageFactory*	_pStorageFactory = nullptr;
	std::function<bool(const MrcMessage* data, MrcRecvContext& ctx)> _OnMessageCallback;

protected:
	void _Refresh_All_CPIDs(int64_t net_time);
	void _Refresh_CPIDs(int64_t net_time, MrcSwarmRelayPtr& core);

public:
	MrcExtMessageRelaySwarms(NetworkServiceCore* net, std::function<bool(const MrcMessage* data, MrcRecvContext& ctx)> func_callback_recvdata)
		: _pNetCore(net)
		, _OnMessageCallback(func_callback_recvdata)
	{}

	void				Init(StorageFactory* stg){ _pStorageFactory = stg; }
	MrcSwarmRelayPtr	Get(MrcContactPointNum pd_id);
	MrcSwarmRelayPtr	Get(const DhtAddress* swarm_addr, bool auto_create);
	bool				Remove(const DhtAddress* swarm_addr);
	bool				Active(const DhtAddress* swarm_addr);
	bool				Dump(rt::BufferEx<DhtAddress>& out);
	void				ForEach(std::function<void(MrcSwarmRelayPtr& core)> callback);

	void				DetachIdleSwarms();
	void				Clear();
	void				Sync();
	void				OnTick(UINT tick);
};

class MessageRelayCore: public AsyncApiHandler
{
	friend class MrcMessageDisassembler;

protected:
	THISCALL_POLYMORPHISM_DECLARE(bool, true, OnMsgRecv, const MrcMessage* data, MrcRecvContext& ctx);
	LPVOID				_OnRecvCallbackObject = nullptr;
	THISCALL_MFPTR		_OnRecvCallbackFunc;
	// push data to upper level, call this when a MrcMessage is received and checked by pow & hash
	// upper level return false if the data is invalid
	bool				_OnMsgRecv(const MrcMessage* msg, MrcRecvContext& ctx){ return _OnRecvCallbackObject?THISCALL_POLYMORPHISM_INVOKE(OnMsgRecv, _OnRecvCallbackObject, _OnRecvCallbackFunc, msg, ctx):_OnMsgDefault(msg, ctx); }
	bool				_OnMsgDefault(const MrcMessage* msg, MrcRecvContext& ctx);

protected:
	NetworkServiceCore*			_pNetCore = nullptr;
	MrcMediaRelayCore*			_pMediaRelay = nullptr;
	MrcContactsControl			_ContactsControl;
	MrcMessageRelaySwarm		_MainSwarm;
	MrcExtMessageRelaySwarms	_ExtendedSwarms;
	DhtAddress					_LocalNodeDeviceId; // set by MyDevices module
	StorageFactory*				_pStorageFactory;

	void			_OnRecvInMainSwarm(LPCVOID pData, UINT len, const PacketRecvContext& ctx);		// hook up with NetworkServiceCore for receiving data 'y'
	void			_OnRecvInExtendedSwarm(LPCVOID pData, UINT len, const PacketRecvContext& ctx);	// hook up with NetworkServiceCore for receiving data 'Y'
	bool			_OnCommand(const os::CommandLine& cmd, rt::String& out);						// hook up with NetworkServiceCore for command prompt
	auto			_GetMrcSwarmRelay(const DhtAddress* swarm_addr) -> MrcMessageRelaySwarm*;

protected:
	struct ApiMessagePushSelect
	{
		enum {
			MPS_APP = 1<<0,
			MPS_CONVERSATION = 1<<1,
		};
		DWORD			Flag = 0;
		uint32_t		App;
		PublicKey		Conversation;
		uint32_t		PushTopicIndex;
		volatile int	SubscriberCount = 0;
		bool			operator == (const ApiMessagePushSelect& x) const;
		bool			IsMatch(const MrcEnvelope& msg, const PublicKey* conversation) const;
	};
	os::ThreadSafeMutable<rt::BufferEx<ApiMessagePushSelect>>	_ApiMessageTopics;

	virtual bool	OnApiInvoke(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp);
	bool			_ApiPrepareMessageSend(MrcMessageAssembler& assem, const rt::String_Ref& arg, DhtAddress& swarm, bool& is_default_swarm, LocalApiResponder* resp) const;
	void			_ApiMessageReceived(const MrcMessageDisassembler& msg, const MrcRecvContext& ctx);
	bool			_ApiInvokeSocial(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp);
	bool			_ApiInvokeMsg(const rt::String_Ref& action, const rt::String_Ref& arguments, LocalApiResponder* resp);
	void			_ApiMessageJsonify(rt::Json& json, const MrcMessageDisassembler& msg, const MrcRecvContext& ctx) const;
	auto			_ApiContacts() -> MrcContactsRepository*;

public:
	MessageRelayCore(NetworkServiceCore* net);
	~MessageRelayCore(){ Term(); }

	auto&			GetContactsControl(){ return _ContactsControl; }
	bool			HasContacts() const { return _ContactsControl.HasContracts(); }
	auto*			GetContacts() const { return _ContactsControl.GetContacts(); }
	void			SetContacts(MrcContactsRepository* c){ _ContactsControl._pContacts = c; }
	bool			HasMediaCore() const { return _pMediaRelay; }

	auto&			GetLocalNodeDeviceId() const { return _LocalNodeDeviceId; }
	void			SetLocalNodeDeviceId(const DhtAddress& x){ _LocalNodeDeviceId = x; }
	auto*			Net() const { return _pNetCore; }

	bool			Init(UINT default_swarm_id, StorageFactory* storage_factory, bool media_core_suspended = false); // traditional dag swarm, MagicCode 'y'
	bool			Join(const DhtAddress* swarm_addr); // overlayed dag swarm, MagicCode 'Y'
	bool			Leave(const DhtAddress* swarm_addr); 
	bool			Active(const DhtAddress* swarm_addr);
	void			DetachAllExtendedSwarms() { _ExtendedSwarms.Clear(); }

	// operation with swarm_addr, nullptr means traditional
	bool			IsMediaCoreDelayed() const;
	void			ResumeMediaCore();
	void			Term();
	void			OnTick(UINT tick);	// hook up with NetworkServiceCore for driving task
	void			Replay(int64_t from, int64_t to, MrcRecvContext::SourceType source, const DhtAddress* swarm_addr = nullptr);
	void			Replay(int64_t from, int64_t to, const ext::fast_set<MrcContactPointNum>& cps, MrcRecvContext::SourceType source, const DhtAddress* swarm_addr = nullptr);
	void			StopReplay(const DhtAddress* swarm_addr = nullptr);
	//void			Replay(osn_messages* messages, MrcRecvContext::SourceType source, const DhtAddress* swarm_addr = nullptr);
	int				Broadcast(const MrcMessage& packet, const NetworkAddress* skip = nullptr, const DhtAddress* swarm_addr = nullptr);
	MrcMsgHash 		BroadcastEnvelope(const MrcEnvelope& envelope, int64_t ttl_sec, bool directly_recv_by_self = true, const DhtAddress* swarm_addr = nullptr);

	void			GetPooled(const DhtAddress* swarm_addr, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit, rt::String& out);
	void			GetPooled(const DhtAddress* swarm_addr, int64_t from, int64_t to, MrcAppId app, uint16_t action, uint16_t limit, LocalApiResponder* resp);
	int64_t			GetMissingTime(int64_t from, const DhtAddress* swarm_addr = nullptr);
	int64_t			GetLastRecvLocalTime(const DhtAddress* swarm_addr = nullptr);
	void			GetWorkload(rt::String& out, const DhtAddress* swarm_addr = nullptr);
	bool			GetWorkload(MrcWorkload& out, const DhtAddress* swarm_addr = nullptr);
	void			SetOnMessageCallback(LPVOID obj, const THISCALL_MFPTR& data_recv = nullptr){ _OnRecvCallbackObject = obj; _OnRecvCallbackFunc = data_recv; }

	// Contacts
	void			UpdateContactPoints(bool contact_dirty);

	// Media Core
	auto			GetMediaWorkload() -> MrcMediaWorkload;
	bool			SaveMedia(uint8_t mime, const GdpData& data, MrcMediaOffloadItem& out, const DhtAddress* swarms, uint32_t swarm_count);
	GdpData			LoadMedia(const GdpHash& hash, const GdpAsyncDataFetch* async_cb, uint8_t priority);
	bool			LoadMedia(const GdpHash& hash, rt::BufferEx<BYTE>& out);
	int				GetMediaAvailability(const GdpHash& hash); // [0, 1000], -1 for non-existed
	bool			ExportMedia(const GdpHash& hash, const char* dest, rt::String* opt_final_path = nullptr);
	bool			RetainMedia(const GdpHash& hash, uint32_t ttl_days, MrcMediaOffloadItem& out); // forwarding existing media
	void			CancelPendingLoads();
	void			DiscoverOffloadsMediaFromAnonymousMessage(const MrcEnvelope& msg, const DhtAddress* swarm_addr);

	// operation for all swarm 
	void			Awaken() { Sync(); }
	void			Sync();
	LONGLONG 		GetTime() const;
	bool			GetAccessPoints(NodeAccessPoints& aps, UINT size_limit);
	void			CleanUnusefulData(os::ProgressReport& prog);
};

} // namespace upw
