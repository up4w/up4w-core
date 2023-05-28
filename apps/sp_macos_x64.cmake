
find_library(APPKIT_LIBRARY AppKit)
if (NOT APPKIT_LIBRARY)
	message(STATUS "AppKit.framework NOT found!")
else()
	message(STATUS "AppKit.framework found! ${APPKIT_LIBRARY}")
endif()

find_library(IOKIT_LIBRARY IOKit)
if (NOT IOKIT_LIBRARY)
	message(STATUS "IOKit.framework NOT found!")
else()
	message(STATUS "IOKit.framework found! ${IOKIT_LIBRARY}")
endif()

find_library(SECURITY_LIBRARY Security)
if (NOT SECURITY_LIBRARY)
	message(STATUS "Security.framework NOT found!")
else()
	message(STATUS "Security.framework found! ${SECURITY_LIBRARY}")
endif()


set(DEP_LIBS 
	libippvm.a
	libipps.a
	libippi.a
	libippcc.a
	libippch.a
	libippcore.a
	libippcp.a
	libippcv.a
	libippdc.a

	${APPKIT_LIBRARY}
	${IOKIT_LIBRARY}
	${SECURITY_LIBRARY}
)