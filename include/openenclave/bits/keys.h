// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_KEYS_H
#define _OE_KEYS_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

/**
* Get a secret SGX key.
*
* Call this function to get a secret SGX key from processor.
*
* @param sgxKeyRequest The parameter points to the KEYREQUEST structure that
* describes which key and how it should be derived. This parameter must point
* to a readable memory block inside enclave.
* @param sgxKey The parameter points to SGX_Key structure where the key will be
* returned. This parameter must point to a writable memory block inside
* enclave. It will not be changed if this function fails.
*
* @retval OE_OK Request succeeded and the key is written to **sgxKey**.
*  **sgxKey** is not modified if the return value is not OE_OK.
* @retval OE_INVALID_CPUSVN **sgxKeyRequest** contains an invalid CPUSVN.
* @retval OE_INVALID_ISVSVN **sgxKeyRequest** contains an invalid ISVSVN.
* @retval OE_INVALID_KEYNAME **sgxKeyRequest** contains an invalid KEYNAME.
* @retval OE_INVALID_PARAMETER Any other invalid parameter was specified.
* @retval OE_UNEXPECTED An unexpected error occurred.
*
*/
oe_result_t oe_get_key(const SGX_KeyRequest* sgxKeyRequest, SGX_Key* sgxKey);

OE_EXTERNC_END

#endif /* _OE_KEYS_H */
