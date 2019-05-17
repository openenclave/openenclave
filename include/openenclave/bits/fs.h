// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_FS_H
#define _OE_BITS_FS_H

/*
**==============================================================================
**
** This file defines functions for loading internal modules that are part of
** the Open Enclave core.
**
**==============================================================================
*/

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Name of the non-secure host file system (passed to **mount()** as the
 * **filesystemtype** parameter).
 */
#define OE_HOST_FILE_SYSTEM "oe_host_file_system"

/**
 * Name of the secure Intel protected file system (passed to **mount()** as the
 * **filesystemtype** parameter).
 */
#define OE_SGX_FILE_SYSTEM "oe_sgx_file_system"

OE_EXTERNC_END

#endif /* _OE_BITS_FS_H */
