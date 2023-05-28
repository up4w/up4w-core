#include <chrono>
#include <thread>
#include <cstdlib>
#include <string>
#include <stdio.h>

#if defined(WIN32)
#include <filesystem>
#define get_temp_path std::filesystem::temp_directory_path().string()+"\\"
#define IMPORT_DLL __declspec(dllimport)
#else
#define get_temp_path "/var/tmp/"
#define IMPORT_DLL 
#endif

extern "C" IMPORT_DLL int	start(const char* str);
extern "C" IMPORT_DLL void	stop();
extern "C" IMPORT_DLL int	get_api_port();
extern "C" IMPORT_DLL bool	is_want_exit();

int main(int argc, char** argv)
{
	std::string cmd = "-data:\"";
	cmd += get_temp_path;
	cmd += "runner\"";

	int r = start(cmd.c_str());
	if (r)
	{
		printf("API Port: %d", get_api_port());
		while (!is_want_exit())
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		stop();
	}
	
}