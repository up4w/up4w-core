#include "../netsvc_core.h"

#include "mlt_packet_cipher.h"

#include "mlt_packet.h"


namespace upw
{

constexpr uint32_t MLT_Packet::PKT_MESSAGE_DATA_SLICE::messageSliceSize;
constexpr uint32_t MLT_Packet::PKT_FILE_SLICE::fileSliceSize;
constexpr uint32_t MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock;
constexpr uint32_t MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileBlockSize;
static_assert(MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock % 8 == 0, "MLT_Packet::PKT_FILE_REQUEST_BLOCK::fileNumSlicesPerBlock must be multiple of 8");

} // namespace upw
