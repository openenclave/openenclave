/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#if defined(OE_USE_OPTEE) && defined(_OE_ENCLAVE_H)
    #ifndef __NEED_struct_timeval
    # define __NEED_struct_timeval
    #endif

    #include <bits/alltypes.h>
#else
    #include <stdint.h>

    typedef int64_t __time64_t;

    #if !defined(_TIME_T_DEFINED_) && !defined(__time_t_defined)
    # ifdef _USE_32BIT_TIME_T
    typedef int32_t __time32_t;
    typedef __time32_t time_t;
    # else
    typedef __time64_t time_t;
    # endif
    # define _TIME_T_DEFINED_
    # define __time_t_defined
    #endif

    #if (!defined(_WINSOCKAPI_) && !(defined(__timeval_defined) || defined(_STRUCT_TIMEVAL)))
    struct timeval {
        long tv_sec;
        long tv_usec;
    };
    #endif
#endif
