// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/trace.h>

#if defined(__x86_64__) || defined(_M_X64)
#include "sgx/enclave.h"
#elif defined(__aarch64__) || defined(_M_ARM64)
#if defined(__linux__)
#include "optee/linux/enclave.h"
#else
#error "OP-TEE is not yet supported on non-Linux platforms."
#endif
#else
#error "Open Enclave is not supported on this architecture."
#endif

#include "core_u.h"

/*
 * This file is separated from traceh.c since the host verification library
 * should not depend on ECALLS.
 */
oe_result_t oe_log_enclave_init(oe_enclave_t* enclave)
{
    initialize_log_config();

    return oe_log_init_ecall(enclave, enclave->path, _log_level);
}
