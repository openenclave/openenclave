// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "asmdefs.h"
#include "asmcommon.inc"

//==============================================================================
//
// uint64_t oe_egetkey(const SgxKeyRequest* sgx_key_request, SgxKey* sgx_key);
//
//     The EGETKEY instruction wrapper.
//
//     Registers:
//         RDI - sgx_key_request
//         RSI - sgx_key
//
//     return:
//         Return values in RAX
//             SGX_EGETKEY_SUCCESS
//             SGX_EGETKEY_INVALID_ATTRIBUTE
//             SGX_EGETKEY_INVALID_CPUSVN
//             SGX_EGETKEY_INVALID_ISVSVN
//             SGX_EGETKEY_INVALID_KEYNAME
//==============================================================================
.globl oe_egetkey
.type oe_egetkey, @function
oe_egetkey:
.cfi_startproc
    movq %rbx, %rdx
    movq %rdi, %rbx
    movq %rsi, %rcx

    // Execute EGETKEY.
    movq $ENCLU_EGETKEY, %rax
    ENCLU

    movq %rdx, %rbx
    // EGETKEY return value is put in RAX by the instruction.
    ret
.cfi_endproc
