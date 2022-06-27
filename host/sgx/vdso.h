// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _HOST_SGX_VDSO_H
#define _HOST_SGX_VDSO_H

#include <openenclave/bits/defs.h>
#include <openenclave/internal/result.h>

extern bool oe_sgx_is_vdso_enabled;

oe_result_t oe_sgx_initialize_vdso(void);

oe_result_t oe_vdso_enter(
    void* tcs,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave);

#endif /* _HOST_SGX_VDSO_H */
