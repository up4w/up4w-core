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
	
	"${UP4W_CORE_DIR}/src/gossip_nettime.cpp"
	"${UP4W_CORE_DIR}/src/local_swarm.cpp"
	"${UP4W_CORE_DIR}/src/nat_passthrough.cpp"
	"${UP4W_CORE_DIR}/src/netsvc_events.cpp"
	"${UP4W_CORE_DIR}/src/netsvc_core.cpp"
	"${UP4W_CORE_DIR}/src/swarm_broadcast.cpp"
	"${UP4W_CORE_DIR}/src/secure_identity.cpp"
	"${UP4W_CORE_DIR}/src/stg/storage_interface.cpp"
	"${UP4W_CORE_DIR}/src/stg/storage_rocksdb.cpp"

	"${UP4W_CORE_DIR}/src/api/local_api.cpp"
	"${UP4W_CORE_DIR}/src/api/api_handlers.cpp"
	"${UP4W_CORE_DIR}/src/api/core_handler.cpp"
	"${UP4W_CORE_DIR}/src/api/api_errors.cpp"

	"${UP4W_CORE_DIR}/src/dht/dht.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_base.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_message.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_space.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_tx_nodes.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_txns.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_tx_swarm.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_tx_joinswarm.cpp"
	"${UP4W_CORE_DIR}/src/dht/dht_tx_connswarm.cpp"

	"${UP4W_CORE_DIR}/src/gdp/gdp.cpp"
	"${UP4W_CORE_DIR}/src/gdp/gdp_base.cpp"
	"${UP4W_CORE_DIR}/src/gdp/gdp_message.cpp"
	"${UP4W_CORE_DIR}/src/gdp/gdp_task.cpp"

	"${UP4W_CORE_DIR}/src/mlt/mlt.cpp"
	"${UP4W_CORE_DIR}/src/mlt/mlt_link.cpp"
	"${UP4W_CORE_DIR}/src/mlt/mlt_packet.cpp"
	"${UP4W_CORE_DIR}/src/mlt/mlt_packet_incoming.cpp"
	"${UP4W_CORE_DIR}/src/mlt/mlt_packet_outgoing.cpp"
	"${UP4W_CORE_DIR}/src/mlt/mlt_tunnel.cpp"
	"${UP4W_CORE_DIR}/src/mlt/mlt_message.cpp"
	"${UP4W_CORE_DIR}/src/mlt/mlt_file_transfer.cpp"

	"${UP4W_CORE_DIR}/src/mrc/mrc.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_assemble.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_attachments.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_base.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_controls.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_contacts.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_dissemble.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_media_core.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_message.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_swarm.cpp"
	"${UP4W_CORE_DIR}/src/mrc/mrc_api.cpp"

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
