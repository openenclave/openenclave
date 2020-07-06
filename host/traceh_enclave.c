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

#if !defined(OE_USE_BUILTIN_EDL)
/**
 * Declare the prototype of the following function to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_log_init_ecall(
    oe_enclave_t* enclave,
    const char* enclave_path,
    uint32_t log_level);

/**
 * Make the following ECALL weak to support the system EDL opt-in.
 * When the user does not opt into (import) the EDL, the linker will pick
 * the following default implementation. If the user opts into the EDL,
 * the implemention (which is also weak) in the oeedger8r-generated code will
 * be used. This behavior is guaranteed by the linker; i.e., the linker will
 * pick the symbols defined in the object before those in the library.
 */
oe_result_t _oe_log_init_ecall(
    oe_enclave_t* enclave,
    const char* enclave_path,
    uint32_t log_level)
{
    OE_UNUSED(enclave);
    OE_UNUSED(enclave_path);
    OE_UNUSED(log_level);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_log_init_ecall, oe_log_init_ecall);

#endif

/*
 * This file is separated from traceh.c since the host verification library
 * should not depend on ECALLS.
 */
oe_result_t oe_log_enclave_init(oe_enclave_t* enclave)
{
    initialize_log_config();

    return oe_log_init_ecall(enclave, enclave->path, _log_level);
}
