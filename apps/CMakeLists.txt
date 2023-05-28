# CMakeList.txt : CMake project for hello_up4w, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project("up4w_core")

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

# Check system, probe paths, add os libs....
include("framework.cmake")

unset(UP4W_CORE_DIR)
unset(MINI_POSIX_DIR)

unset(DEP_LIB_DIR)
unset(DEP_LIBS)

unset(UP4W_SRCS)


get_filename_component(ROOT_DIR "${CMAKE_SOURCE_DIR}/.." ABSOLUTE)

set(UP4W_CORE_DIR "${ROOT_DIR}")
set(MINI_POSIX_DIR "${ROOT_DIR}/externs/miniposix")

set(DEP_LIB_DIR "${ROOT_DIR}/libs")


if (EXISTS "${CMAKE_SOURCE_DIR}/CMakeLists.user")
	include("${CMAKE_SOURCE_DIR}/CMakeLists.user")
endif()

if (TARGET_PLATFORM STREQUAL "WINDOWS_X64")
	include("sp_windows_x64.cmake")
elseif (TARGET_PLATFORM STREQUAL "MACOS_X64")
	include("sp_macos_x64.cmake")
elseif (TARGET_PLATFORM STREQUAL "LINUX_X64")
	include("sp_linux_x64.cmake")
else()
	message( FATAL_ERROR "unsupported target platform")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXT_CXX_FLAGS} -DNET_BROADCAST_ALLPEERS ")

message("CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE MATCHES "Rel")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DPLATFORM_DISABLE_LOG")
endif()
message("CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")

set(UP4W_SRCS
	"${MINI_POSIX_DIR}/essentials.cpp"
	"${MINI_POSIX_DIR}/core/ext/botan/botan.cpp"
	"${MINI_POSIX_DIR}/core/ext/lib_inc.c"
	"${MINI_POSIX_DIR}/core/ext/rocksdb/rocksdb.cpp"
	"${MINI_POSIX_DIR}/core/inet/datagram_pump.cpp"
	"${MINI_POSIX_DIR}/core/inet/tinyhttpd.cpp"
	"${MINI_POSIX_DIR}/core/inet/tinyhttpd_fileserv.cpp"
	"${MINI_POSIX_DIR}/core/inet/tinyhttpd_websocket.cpp"
	"${MINI_POSIX_DIR}/core/os/file_zip.cpp"

	"${UP4W_CORE_DIR}/externs/libsodium/libs_inline_c_0.cpp"
	"${UP4W_CORE_DIR}/externs/libsodium/libs_inline_c_1.cpp"
	"${UP4W_CORE_DIR}/externs/libsodium/libs_inline_c_2.cpp"
	"${UP4W_CORE_DIR}/externs/libsodium/libs_inline_c_3.cpp"
	"${UP4W_CORE_DIR}/externs/libsodium/libs_inline_c_4.cpp"
	"${UP4W_CORE_DIR}/oxd_net.cpp"
	"${UP4W_CORE_DIR}/src/upw.cpp"
)

if (${TARGET_PLATFORM} STREQUAL "MACOS_X64")
	set(UP4W_SRCS
		${UP4W_SRCS}
		"${MINI_POSIX_DIR}/core/os/objc_wrap.mm"
	)
endif()

include_directories(
	"${UP4W_CORE_DIR}/externs/libsodium/libsodium/src/libsodium/include/sodium"
)

link_directories(
	${DEP_LIB_DIR}
)

add_executable (up4w_core_executable
	${UP4W_SRCS}
	"core.cpp"
)
target_link_libraries (up4w_core_executable
	${DEP_LIBS}
)


add_library (up4w_core_shared SHARED
	${UP4W_SRCS}
	"core.cpp"
)
target_link_libraries (up4w_core_shared
	${DEP_LIBS}
)
SET_TARGET_PROPERTIES(up4w_core_shared PROPERTIES LINKER_LANGUAGE C)


add_executable (up4w_core_shared_runner
	"runner.cpp"
)
target_link_libraries (up4w_core_shared_runner
	"up4w_core_shared"
)
add_dependencies(up4w_core_shared_runner
	up4w_core_shared
)


add_custom_target(build_all
)
add_dependencies(build_all
	up4w_core_shared
	up4w_core_shared_runner
	up4w_core_executable
)
