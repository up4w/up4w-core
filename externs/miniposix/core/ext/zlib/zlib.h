#pragma once

/** \defgroup zlib zlib
 * @ingroup ext
 *  @{
 */

#include "../../os/predefines.h"
#include "../../rt/runtime_base.h"

#ifdef PLATFORM_INTEL_IPP_SUPPORT
#include "../ipp/ipp_config.h"
#include "../ipp/ipp_zlib/zlib.h"
#else
//#define Z_PREFIX
#include "zlib/zlib.h"
#endif

namespace rt
{
/** \defgroup zlib zlib
 * @ingroup ext
 *  @{
 */
INLFUNC bool zlib_encode(LPCVOID pSrc, UINT SrcLen, LPVOID pDst, UINT& DstLen, int Compression_Level = -1)
{
	z_stream defstrm;

	defstrm.zalloc = Z_NULL;
	defstrm.zfree = Z_NULL;
	defstrm.opaque = Z_NULL;
	defstrm.avail_in = SrcLen;
	defstrm.next_in = (Bytef*)pSrc;
	defstrm.next_out = (Bytef*)pDst;
	defstrm.avail_out = DstLen;

	if(deflateInit2(&defstrm, Compression_Level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)!= Z_OK)
		return false;

	int ret = deflate(&defstrm, Z_FINISH);
	deflateEnd(&defstrm);
	if(ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
		return false;

	DstLen = (UINT)defstrm.total_out;
	return true;
}

INLFUNC bool zlib_decode(LPCVOID pSrc, UINT SrcLen, LPVOID pDst, UINT& DstLen)
{
	z_stream infstrm;
					
	infstrm.zalloc = Z_NULL;
	infstrm.zfree = Z_NULL;
	infstrm.opaque = Z_NULL;
	infstrm.avail_in = SrcLen;
	infstrm.next_in = (Bytef*)pSrc;
	infstrm.next_out = (Bytef*)pDst;
	infstrm.avail_out = DstLen;
					
	// Inflate using raw inflation
	if (inflateInit2(&infstrm,-15) != Z_OK)return false;
	int ret = inflate(&infstrm, Z_FINISH);
	inflateEnd(&infstrm);
	if(ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
		return false;

	DstLen = (UINT)infstrm.total_out;
	return true;
}
/** @}*/
} // namespace rt
/** @}*/
