#pragma once



#include "./core/rt/string_type.h"
#include "./core/rt/string_type_ops.h"
#include "./core/rt/buffer_type.h"
#include "./core/rt/json.h"

#include "./core/os/file_dir.h"
#include "./core/os/multi_thread.h"
#include "./core/inet/inet.h"

/*** Compiler/Linker Options on Linux ***/
// In [ Global Settings ]
// C++ Compiler Options: -std=c++14;-pthread;-mlzcnt;  (change -Wall to -w)
// Linker Options: -pthread;-ldl;-lX11;-mlzcnt;
// IPP Library: libippj_l.a;libippac_l.a;libippcp_l.a;libippi_l.a;libippsc_l.a;libippcc_l.a;libippcv_l.a;libipps_l.a;libippch_l.a;libippdc_l.a;libippm_l.a;libippvc_l.a;libippcore_l.a;libippdi_l.a;libippr_l.a;libippvm_l.a

/*** Compiler/Linker Options on Mac ***/
// Add file /src/os/objc_wrap.mm to the project
// General Tab -> Linked Frameworks and Libraries
// IOKit.framework, AppKit.framework
// IPP Library: all files in /libs/mac/*.a

/** @}*/