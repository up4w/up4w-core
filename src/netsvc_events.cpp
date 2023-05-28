#include "netsvc_events.h"
#include "netsvc_types.h"
#include "../externs/miniposix/core/ext/sparsehash/sparsehash.h"


namespace upw
{

namespace _details
{

os::ThreadSafeMutable<rt::BufferEx<CoreEventSink*>>				EventSinks;
os::ThreadSafeMutable<ext::fast_map<ULONGLONG, rt::String>>		EventNames;

} // namespace _details


CoreEvents::CoreEvents()
{
}

CoreEvents::~CoreEvents()
{
	_details::EventSinks.Clear();
	_details::EventNames.Clear();
}

void CoreEvents::Subscribe(CoreEventSink* p)
{
	THREADSAFEMUTABLE_UPDATE(_details::EventSinks, g);
	if(g.GetUnmodified().Find(p) >= 0)return;

	g->push_back(p);
}

void CoreEvents::Unsubscribe(CoreEventSink* p)
{
	THREADSAFEMUTABLE_UPDATE(_details::EventSinks, g);
	auto pos = g.GetUnmodified().Find(p);
	if(pos < 0)return;

	g->erase(pos);
}

void CoreEvents::RegisterEvent(DWORD mod_id, DWORD evt_id, const rt::String_Ref& name)
{
	THREADSAFEMUTABLE_UPDATE(_details::EventNames, g);
	g->operator[]((((ULONGLONG)mod_id)<<32) | evt_id | EVENT_ID_MASK) = name;
}

bool CoreEvents::RegisterModule(DWORD mod_id, const rt::String_Ref& name)
{
	THREADSAFEMUTABLE_UPDATE(_details::EventNames, g);
	ULONGLONG i = (((ULONGLONG)mod_id)<<32) | INFINITE;

	auto& names = g.GetUnmodified();
	
	auto it = names.find(i);
	if(it == names.end())
	{
		g->operator [](i) = name;
		return true;
	}
	else
	{
		if(it->second != name)
		{
			_LOG_WARNING("[NET] Event Module :"<<mod_id<<" has been registered as "<<it->second);
		}

		return false;
	}
}

const rt::String_Ref& CoreEvents::GetModuleName(DWORD mod_id) const
{
	THREADSAFEMUTABLE_SCOPE(_details::EventNames);
	auto& names = _details::EventNames.GetImmutable();
	auto it = names.find((((ULONGLONG)mod_id)<<32) | INFINITE);
	if(it == names.end())
	{	
		static const rt::String_Ref _("_[UNK_MOD]");
		return _;
	}
	else return it->second;
}

const rt::String_Ref& CoreEvents::GetEventName(DWORD mod_id, DWORD msg_id) const
{
	THREADSAFEMUTABLE_SCOPE(_details::EventNames);
	auto& names = _details::EventNames.GetImmutable();
	auto it = names.find((((ULONGLONG)mod_id)<<32) | msg_id | EVENT_ID_MASK);
	if(it == names.end())
	{	
		static const rt::String_Ref _("_[UNK_EVT]");
		return _;
	}
	else return it->second;
}

void CoreEvents::Notify(DWORD mod_id, DWORD evt_id, LPCSTR p, UINT sz)
{
#if !defined(PLATFORM_RELEASE_BUILD) || !defined(PLATFORM_SUPPRESS_DEBUG_LOG)
	rt::JsonBeautified jb;
	rt::String_Ref param = rt::SS("null");
	if(sz)
	{
		if(p[0] == '[' || p[0] == '{')
		{
			jb.Beautify(rt::String_Ref(p, sz), 2, 60);
			param = jb;
		}
		else
		{
			param = rt::String_Ref(p, sz);
		}
	}

	_LOGC_VERBOSE("[EVT]: "<<GetModuleName(mod_id).TrimBefore('_')<<"::"<<GetEventName(mod_id, evt_id).TrimBefore('_')<<" param="<<param);
#endif
		
	{	THREADSAFEMUTABLE_SCOPE(_details::EventSinks);
		auto& sinks = _details::EventSinks.GetImmutable();
		for(auto& it: sinks)
			it->OnCoreEventNotify(mod_id, evt_id, p, sz);
	}

#if !defined(PLATFORM_RELEASE_BUILD) || !defined(PLATFORM_SUPPRESS_DEBUG_LOG)
	THREADSAFEMUTABLE_SCOPE(_details::EventNames);
	auto& names = _details::EventNames.GetImmutable();
	auto nit = names.find((((ULONGLONG)mod_id)<<32) | evt_id | EVENT_ID_MASK);
	if(nit == names.end())
	{
		_LOGC_WARNING("[NET] Event (m:"<<mod_id<<", e:"<<evt_id<<") is not registered");
	}
#endif
}

rt::String& CoreEvents::Jsonify(rt::String& append) const
{
	THREADSAFEMUTABLE_SCOPE(_details::EventNames);
	auto& names = _details::EventNames.GetImmutable();

	append += "[";

	for(auto it : names)
	{
		auto id = it.first;
		auto name = it.second;

		UINT mod_id = (UINT)(id >> 32);
		UINT evt_id = (UINT)id;

		if(evt_id != INFINITE)
			evt_id = evt_id & ~EVENT_ID_MASK;

		/*
		if(id & INFINITE == INFINITE)
			append += rt::SS("M:") + (id>>32) + ":" + name + "\n";
		else
			append += rt::SS("E:") + (id >> 32) + "," + (id & INFINITE ^ EVENT_ID_MASK) + ":" + name + "\n";
		*/

		append += "\n[ \"" + name + "\"," + id +","+mod_id+","+evt_id+ "],";
	}

	append.EndClosure(']');
	return append;
}


} // namespace upw