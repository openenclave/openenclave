// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "asmdefs.h"
#include "asmcommon.inc"

//==============================================================================
//
// uint64_t OE_EGetKey(const SgxKeyRequest* sgxKeyRequest, SgxKey* sgxKey);
//
//     The EGETKEY instruction wrapper.
//
//     Registers:
//         RDI - sgxKeyRequest
//         RSI - sgxKey
//
//     return:
//         Return values in RAX
//             SGX_EGETKEY_SUCCESS
//             SGX_EGETKEY_INVALID_ATTRIBUTE
//             SGX_EGETKEY_INVALID_CPUSVN
//             SGX_EGETKEY_INVALID_ISVSVN
//             SGX_EGETKEY_INVALID_KEYNAME
//==============================================================================
.globl OE_EGetKey
.type OE_EGetKey, @function
OE_EGetKey:
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
