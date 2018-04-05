// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_KEYS_H
#define _OE_KEYS_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/**
* Get a secret SGX key.
*
* Call this function to get a secret SGX key from processor.
*
* @param sgxKeyRequest The parameter points to the KEYQUEST structure that
* describes which key and how it should be derived. This parameter must point
* to a readable memory block inside enclave.
* @param sgxKey The parameter points to Sgx_Key structure where the key will be
* returned. This parameter must point to a writable memory block inside
* enclave. It will not be changed if this function fails.
*
* @returns This function returns an OE_OK and the requested key is written to
*  sgxKey if success, otherwise the sgxKey will be not changed and return
*  following errors:
*  OE_INVALID_PARAMETER - invalid parameter.
*  OE_INVALID_CPUSVN - invalid CPUSVN in key request.
*  OE_INVALID_ISVSVN - invalid ISVSVN in key request.
*  OE_INVALID_KEYNAME - invalid KEYNAME in key request.
*  OE_UNEXPECTED - unexpected error.
*
*/
OE_Result OE_GetKey(const Sgx_KeyRequest* sgxKeyRequest, Sgx_Key* sgxKey);

OE_EXTERNC_END

#endif /* _OE_KEYS_H */
