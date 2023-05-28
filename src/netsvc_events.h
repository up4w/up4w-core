#pragma once
#include "net_types.h"


/////////////////////////////////////////////////////////////////////////////////
// Command Handling Callback (THISCALL_MFPTR) driven by LocalApi
// from console input or Json Rest Service
// bool Class::Function(const os::CommandLine& cmd, rt::String& out);


/////////////////////////////////////////////////////////////////////////////////
// Tick Callback (THISCALL_MFPTR) driven by NetworkServiceCore
// void Class::Function( UINT tick_in_10ms, LONGLONG net_ts_in_ms);


namespace upw
{
struct CoreEventSink;

class CoreEvents: public rt::Singleton<CoreEvents>
{
	friend class rt::Singleton<CoreEvents>;

protected:
	CoreEvents();
	~CoreEvents();

public:
	static const DWORD EVENT_ID_MASK = 0x80000000U;

	void		Subscribe(CoreEventSink* p);
	void		Unsubscribe(CoreEventSink* p);
	void		RegisterEvent(DWORD mod_id, DWORD evt_id, const rt::String_Ref& name);
	bool		RegisterModule(DWORD mod_id, const rt::String_Ref& name);

	void		Notify(DWORD mod_id, DWORD msg_id, LPCSTR json, UINT json_len);
	void		Notify(DWORD mod_id, DWORD msg_id){ Notify(mod_id, msg_id, nullptr, 0); }
	void		Notify(DWORD mod_id, DWORD msg_id, bool x)
				{	if(x)
						Notify(mod_id, msg_id, "true", 4); 
					else
						Notify(mod_id, msg_id, "false", 5);
				}

	void		Notify(DWORD mod_id, DWORD msg_id, LONGLONG x){	rt::tos::Number s(x);	Notify(mod_id, msg_id, s.Begin(), (UINT)s.GetLength()); }
	void		Notify(DWORD mod_id, DWORD msg_id, ULONGLONG x){ rt::tos::Number s(x);	Notify(mod_id, msg_id, s.Begin(), (UINT)s.GetLength()); }
	void		Notify(DWORD mod_id, DWORD msg_id, INT x){	rt::tos::Number s(x);		Notify(mod_id, msg_id, s.Begin(), (UINT)s.GetLength()); }
	void		Notify(DWORD mod_id, DWORD msg_id, UINT x){	rt::tos::Number s(x);		Notify(mod_id, msg_id, s.Begin(), (UINT)s.GetLength()); }
	void		Notify(DWORD mod_id, DWORD msg_id, float x){ rt::tos::Number s(x);		Notify(mod_id, msg_id, s.Begin(), (UINT)s.GetLength()); }
	void		Notify(DWORD mod_id, DWORD msg_id, double x){ rt::tos::Number s(x);		Notify(mod_id, msg_id, s.Begin(), (UINT)s.GetLength()); }

	void		NotifyWith(DWORD mod_id, DWORD msg_id, LPCSTR x){ NotifyWith(mod_id, msg_id, rt::String_Ref(x)); }
	template<typename T>    // for string/json
	void		NotifyWith(DWORD mod_id, DWORD msg_id, T&& str)
				{	UINT len = (UINT)str.GetLength();
					LPSTR p = (LPSTR)alloca(len + 2);
					VERIFY(len == str.CopyTo(p+1));
					if(p[1] == '{' || p[1] == '[')
						Notify(mod_id, msg_id, p+1, len);
					else
					{	p[0] = '"';
						p[len + 1] = '"';
						Notify(mod_id, msg_id, p, len+2);
					}
				}

	const rt::String_Ref& GetModuleName(DWORD mod_id) const;
	const rt::String_Ref& GetEventName(DWORD mod_id, DWORD msg_id) const;

	rt::String& Jsonify(rt::String& append) const;
};

template<typename... ARGS>
void CoreEvent(ARGS... args){ CoreEvents::Get().Notify(args...); }

template<typename... ARGS>
void CoreEventWith(ARGS... args){ CoreEvents::Get().NotifyWith(args...); }

} // namespace upw

#define DEF_COREEVENTS_BEGIN(mod_id)	{	if(upw::CoreEvents::Get().RegisterModule(mod_id, #mod_id)){	\
											DWORD __mod_id = mod_id;
#define DEF_COREEVENT(evt_id)				upw::CoreEvents::Get().RegisterEvent(__mod_id, evt_id, #evt_id);
#define DEF_COREEVENTS_END				}}