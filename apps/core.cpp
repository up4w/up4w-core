#include "../src/upw.h"

void append_options(os::CommandLine& cmd)
{

#if defined(PLATFORM_DEBUG_BUILD)
	cmd.SetOption("con");
#endif

	if (!cmd.HasOption("api"))
		cmd.SetOption("api");
}

int main(int argc, char** argv)
{
	os::CommandLine	cmd(argc, argv);
	append_options(cmd);

	using namespace upw;

	if (start(cmd))
	{
		upw_status st = { 0 };
		int api_port = 0;
		while (!st.want_exit)
		{
			os::Sleep(250);
			status(&st);
			if (!api_port && st.api_port > 0)
			{
				api_port = st.api_port;
				_LOG_HIGHLIGHT("API Port: " << api_port);
			}
		}
	}

	stop();
}

#if defined(WIN32)
#define EXPORT_DLL __declspec(dllexport)
#else
#define EXPORT_DLL
#endif

extern "C" EXPORT_DLL int start(const char* str)
{
	static os::CommandLine cmd;
	if (cmd.GetOptionCount()) return 0;
	cmd.Parse(str);
	if (!cmd.GetOptionCount()) return 0;

	append_options(cmd);

	return upw::start(cmd)? 1 : 0;
}

extern "C" EXPORT_DLL void status(upw::upw_status* out)
{
	upw::status(out);
}

extern "C" EXPORT_DLL void stop()
{
	upw::stop();
}

extern "C" EXPORT_DLL int get_api_port()
{
	upw::upw_status st;
	upw::status(&st);
	return st.api_port;
}

extern "C" EXPORT_DLL bool	is_want_exit()
{
	upw::upw_status st;
	upw::status(&st);
	return st.want_exit;
}
