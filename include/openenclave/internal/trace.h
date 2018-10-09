// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TRACE_H
#define _OE_TRACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#define OE_PRINTF oe_host_printf
#else
#include <stdio.h>
#define OE_PRINTF printf
#endif

#define OE_TRACE_LEVEL_NONE 0
#define OE_TRACE_LEVEL_ERROR 1
#define OE_TRACE_LEVEL_INFO 2

OE_EXTERNC_BEGIN

#ifdef __cplusplus
#define OE_CATCH _catch
#else
#define OE_CATCH catch
#endif

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_ERROR)
#define OE_TRACE_ERROR(...)     \
    do                          \
    {                           \
        OE_PRINTF(__VA_ARGS__); \
    } while (0)
#else
#define OE_TRACE_ERROR(...)
#endif

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
#define OE_TRACE_INFO(...)      \
    do                          \
    {                           \
        OE_PRINTF(__VA_ARGS__); \
    } while (0)
#else
#define OE_TRACE_INFO(...)
#endif

OE_EXTERNC_END

#endif /* _OE_TRACE_H */
