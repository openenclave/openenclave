// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_COMMON_H
#define _OE_COMMON_COMMON_H

/*
 * This file is intended to be used by code that exists in common folder.
 * It handles the differences between host and enclave header includes so
 * that common code can be written consistently using oe_* methods. When
 * compiling for host, it routes the oe_* prefixed C library calls to
 * standard libc symbols via inline function wrappers in oe_host_* headers.
 */

#ifdef OE_BUILD_ENCLAVE

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdint.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>

#else

#include <openenclave/host.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oe_host_stdio.h"
#include "oe_host_stdlib.h"
#include "oe_host_string.h"

#endif

#endif // _OE_COMMON_COMMON_H
