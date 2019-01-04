/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
/*++

Module Name:

    tcps_settings.h

Abstract:

    SGX platform specific TCPS settings. Defines Platform specific 
    memory management and logging functions.

--*/

#pragma once

#include <stdlib.h>

//  Platform configuration
#define TCPS_LOG_ERROR(...) //TODO: Add SGX specific logging
#define TCPS_LOG(...) //TODO: Add SGX specific logging

#define TCPSALLOC(_s) malloc(_s)
#define TCPSFREE(_p) free(_p)
#define TCPSREALLOC(_p, _s) realloc(_p, _s)
#define TCPSZERO(_p, _s) memset(_p, 0, _s)

#define TCPS_ERROR_TRACE_ENABLED
//#define TCPS_SSL_DEBUG 1
