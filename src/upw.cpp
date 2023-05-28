#include "upw.h"
#include "../src/netsvc_core.h"
#include "../src/dht/dht.h"
#include "../src/swarm_broadcast.h"
#include "../src/gdp/gdp.h"
#include "../src/api/local_api.h"
#include "../externs/miniposix/core/ext/botan/botan.h"


namespace Global
{

class NetCore
{
protected:
	static upw::NetworkServiceCore* _Core;
	static bool _bWantStop;
public:
	static upw::NetworkServiceCore& Get()
	{
		return *GetPtr();
	}
	static upw::NetworkServiceCore* GetPtr()
	{
		if (_bWantStop)
			return nullptr;
		else
		{
			if (!_Core)
				_Core = new upw::NetworkServiceCore();
			return _Core;
		}
	}
	static bool WantExit() { return _bWantStop || _Core->bWantStop; }
	static int ApiPort()
	{
		if (_bWantStop)
			return -1;

		auto& core = Global::NetCore::Get();
		if (core.HasAPI())
			return core.API().GetJsonRpcPort();
		else
			return -1;
	}
	static void Stop()
	{
		if (_bWantStop)
			return;

		_bWantStop = true;
		{
			_Core->Stop();
			delete _Core;
			_Core = nullptr;
		}
	}
};

upw::NetworkServiceCore* NetCore::_Core = nullptr;
bool NetCore::_bWantStop = false;

} // namespace Global

namespace upw
{

bool start(os::CommandLine& cmd)
{
	if(!cmd.HasOption("gnt"))cmd.SetOption("gnt");
	if(!cmd.HasOption("smb"))cmd.SetOption("smb");

	rt::String data_dir = cmd.GetOption("data", ".");
	data_dir = data_dir.TrimTrailingPathSeparator();

	if(cmd.GetOption("dht").IsEmpty())
	{
		DhtAddress DHT_OwnId;
		static const rt::SS nodeid_fn = "/nodeid";

		rt::String str;
		if(os::File::LoadText(data_dir + nodeid_fn, str, 24*1000*3600) && DHT_OwnId.FromString(str)){}
		else
		{
			DHT_OwnId.Random();
			os::File::SaveText(data_dir + nodeid_fn, tos(DHT_OwnId));
		}
		cmd.SetOption("dht", tos(DHT_OwnId));
	}

	{	upw::NetworkServiceCore& core = Global::NetCore::Get();
		core.SetCachePath(data_dir);
		if(core.Start(cmd))
		{
			DhtAddress time_swarm;
			if(time_swarm.FromString(cmd.GetOption("default_swarm")))
			{
				core.SMB().Join(time_swarm, 8);
			}
			else if(time_swarm.FromString(cmd.GetOption("time_swarm")))
				core.DHT().StartConnSwarm(time_swarm);

			_LOG_HIGHLIGHT(	"\n\n"
							"               _   _______  ___ _    _ \n"
							"              | | | | ___ \\/   | |  | |\n"
							"              | | | | |_/ / /| | |  | |\n"
							"              | | | |  __/ /_| | |/\\| |\n"
							"              | |_| | |  \\___  \\  /\\  /\n"
							"               \\___/\\_|      |_/\\/  \\/ \n\n\n");

			return true;
		}
	}

	return false;
}

void stop()
{
	Global::NetCore::Stop();
}

void status(upw_status* out)
{
	if (out)
	{
		out->want_exit = Global::NetCore::WantExit();
		out->api_port = Global::NetCore::ApiPort();
	}
}


} // namespace upw
