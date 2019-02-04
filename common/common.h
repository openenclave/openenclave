// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_COMMON_H
#define _OE_COMMON_COMMON_H

// This file is intended to be used by code that exists in common folder.
// It includes the necessary header files and allows code to be written against
// standard C library.
// When compiling for enclave, it routes the C library calls to enclavelibc
// functions.

#ifdef OE_BUILD_ENCLAVE

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>

// Redefine C library functions to use enclave libc functions.
#define malloc oe_malloc
#define free oe_free

#define strlen oe_strlen

#define printf oe_host_printf

#else

#include <openenclave/host.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#endif

#endif // _OE_COMMON_COMMON_H
