// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../vdso.h"

/* Stub functions to prevent missing symbols on Windows where vDSO
 * is not supported.
 * Note that the reason not using weak symbols on both Windows is
 * that the Windows linker requires this file to have at least one
 * strong symbol that is referenced by other files; i.e., the file
 * cannot have only weak symbols. */
oe_result_t oe_sgx_initialize_vdso(void)
{
    return OE_UNSUPPORTED;
}

oe_result_t oe_vdso_enter(
    void* tcs,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave)
{
    OE_UNUSED(tcs);
    OE_UNUSED(arg1);
    OE_UNUSED(arg2);
    OE_UNUSED(arg3);
    OE_UNUSED(arg4);
    OE_UNUSED(enclave);

    return OE_UNSUPPORTED;
}
