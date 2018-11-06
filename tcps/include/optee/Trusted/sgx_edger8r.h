/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif

#ifdef SIMULATE_TEE
# include "Simulator/oeenclave.h"
#endif

#include "../../../../3rdparty/SGXSDK/include/sgx_edger8r.h"  /* SGX API prototypes to map */
#include <tee_api.h>         /* OP-TEE APIs to map them to */
#include "TcpsRpcOptee.h"

/* We currently assume the macros below are only used from generated code. */

/* In SGX, sgx_ocalloc allocates memory on the rich app's stack, meaning
 * it's per-thread memory.  We currently map this to a normal heap allocation.
 */
#define sgx_ocalloc(x) TEE_Malloc((x), TEE_MALLOC_FILL_ZERO)

/* In SGX, sgx_ocfree frees all memory allocated by any sgx_ocalloc calls
 * on the thread's stack.  We map this to a heap free, and we assume that
 * the generated code only called sgx_ocalloc once and the result is in the
 * "ms" variable.
 */
#define sgx_ocfree() \
    if (ms != NULL) { \
        TEE_Free(ms); \
    }

#define sgx_ocall(id, ptr)  sgx_optee_ocall((id), (ptr), sizeof(*(ptr)))
