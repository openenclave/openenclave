/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
/*++

Module Name:

    tcps_settings.h

Abstract:

    Platform specific TCPS settings. Each platform can include this file
    to specify common TCPS functionality. This includes platform specific
    memory management functions.

--*/
#pragma once

/////////////////////////////////////////////////////////////////////////////////////////
#include <stdint.h>
#include "tcps.h"

#define TCPS_ERROR_TRACE_ENABLED
#define TCPS_UNREFERENCED_PARAMETER(x)  ((void)(x))

int32_t     TcpsInitializePlatformLibrary(void);    // Returns 0 for success, and negative values for errors.
void        TcpsShutdownPlatformLibrary(void);

/////////////////////////////////////////////////////////////////////////////////////////
#ifdef _OE_HOST_H

#include <time.h>
#include <OpteeCalls.h>

#define TCPS_LOG_ERROR(format, ...)     OpteeLibLog(__FUNCTION__ ": Error: "    format "\n", __VA_ARGS__)
#define TCPS_LOG_WARNING(format, ...)   OpteeLibLog(__FUNCTION__ ": Warning: "  format "\n", __VA_ARGS__)
#define TCPS_LOG(format, ...)           OpteeLibLog(__FUNCTION__ ": "           format "\n", __VA_ARGS__)

/////////////////////////////////////////////////////////////////////////////////////////
#else

#include <trace.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <tee_api.h>

#define FIELD_OFFSET(type, field)       ((long)(void*)&(((type *)0)->field))

#define TCPS_LOG_ERROR(...)             EMSG(__VA_ARGS__)
#define TCPS_LOG(...)                   DMSG(__VA_ARGS__)
#define TCPS_LOG_BUFFER(buf, len)       DHEXDUMP((const uint8_t *)(buf), (len))

#define TCPSALLOC(_s)       malloc(_s)
#define TCPSFREE(_p)        free(_p)
#define TCPSREALLOC(_p, _s) realloc(_p, _s)
#define TCPSZERO(_p, _s)    memset(_p, 0, _s)

#include "tcps_time_t.h"
#include "optee/tcps_string_optee_t.h"

#endif /* #ifdef _OE_HOST_H */
/////////////////////////////////////////////////////////////////////////////////////////
