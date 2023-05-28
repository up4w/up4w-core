#pragma once


#include "../../../os/kernel.h"

#ifdef PLATFORM_INTEL_IPP_SUPPORT

#include "../../ipp/ipp_core.h"
#include "../../ipp/inc/ippcp.h"

#else

#include "botan_inc.h"

#endif // #ifdef PLATFORM_INTEL_IPP_SUPPORT

