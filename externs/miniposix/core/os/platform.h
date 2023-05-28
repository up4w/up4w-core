#pragma once



/** \defgroup platform platform
 * @ingroup os
 *  @{
 */
#if defined(PLATFORM_RECOGNIZED)
	#error CFP platform header conflict
#endif

///////////////////////////////////////////////
// Platfrom detection
//	PLATFORM_WIN
//	PLATFORM_IOS
//	PLATFORM_MAC
//	PLATFORM_ANDROID

#if		defined(__ANDROID__)
		#define PLATFORM_ANDROID
		#define PLATFORM_RECOGNIZED
#elif	defined(__APPLE__)
		#include "TargetConditionals.h"
		#if TARGET_OS_IPHONE
		    #define PLATFORM_IOS
		#elif TARGET_IPHONE_SIMULATOR
			#define PLATFORM_IOS
		#else
		    #define PLATFORM_MAC
		#endif
		#define PLATFORM_RECOGNIZED
#elif	defined(_WIN32)
		#define PLATFORM_WIN
		#define PLATFORM_RECOGNIZED
	#if _MSC_VER >= 1900  ///< Visual Studio 2015
	#endif
#elif	defined(__linux__) || defined(__linux)
		#define PLATFORM_LINUX
		#define PLATFORM_RECOGNIZED
#else
		#error Unrecognized Platform
#endif


/**
 * @brief  define this macro project-wisely to prevent using 
 *  of some APIs that are not widely supported
 *  #define PLATFORM_MAX_COMPATIBILITY
 */
#if		defined(PLATFORM_WIN) || defined(PLATFORM_MAC) || defined(PLATFORM_LINUX)

#ifndef	PLATFORM_DISABLE_INTEL_IPP
		#define PLATFORM_INTEL_IPP_SUPPORT
#endif

		#define PLATFORM_OPENGL_SUPPORT

#if defined(PLATFORM_WIN) || defined(PLATFORM_MAC) || defined(PLATFORM_LINUX)
		#define PLATFORM_INTEL_MKL_SUPPORT
#endif

#elif	defined(PLATFORM_IOS) || defined(PLATFORM_ANDROID)
		#define PLATFORM_OPENGL_ES_SUPPORT
#endif

#if	(defined(PLATFORM_WIN) && defined(_WIN64)) || defined(__LP64__)
	#define PLATFORM_64BIT
#else
	#define PLATFORM_32BIT
#endif

#if	defined(PLATFORM_WIN) || defined(PLATFORM_MAC) || defined(PLATFORM_IOS)

#if defined(_DEBUG) || defined(DEBUG)
	#define PLATFORM_DEBUG_BUILD
#else
	#define PLATFORM_RELEASE_BUILD
#endif

#elif defined(PLATFORM_LINUX) || defined(PLATFORM_ANDROID)

#if defined(NDEBUG)
	#define PLATFORM_RELEASE_BUILD
#else
	#define PLATFORM_DEBUG_BUILD
#endif

#endif
/** @}*/
/** @}*/

