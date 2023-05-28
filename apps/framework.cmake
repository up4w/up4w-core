
if (${CMAKE_SIZEOF_VOID_P} STREQUAL "8")
	# TODO: more checks?
else()
	message( FATAL_ERROR "only support x64")
endif()



message("TARGET_PLATFORM: ${CMAKE_CXX_PLATFORM_ID}")
message("COMPILER: ${CMAKE_CXX_COMPILER_ID} \"${CMAKE_CXX_COMPILER}\"")


#[[ CMAKE_CXX_PLATFORM_ID
	windwos-msvc
		Windows
]]
unset(TARGET_PLATFORM)
if (${CMAKE_CXX_PLATFORM_ID} STREQUAL "Windows")
	set(TARGET_PLATFORM "WINDOWS_X64")
elseif(${CMAKE_CXX_PLATFORM_ID} STREQUAL "Darwin")
	set(TARGET_PLATFORM "MACOS_X64")
elseif(${CMAKE_CXX_PLATFORM_ID} STREQUAL "Linux")
	set(TARGET_PLATFORM "LINUX_X64")
else()
	message( FATAL_ERROR "only support Windows, MacOS, Linux")
endif()

