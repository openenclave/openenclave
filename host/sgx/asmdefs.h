// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ASMDEFS_H
#define _ASMDEFS_H

#ifndef __ASSEMBLER__
#include <openenclave/bits/types.h>
#include <openenclave/internal/context.h>
#include <openenclave/internal/sgx/ecall_context.h>
#include <stdint.h>
#endif

#ifdef __ASSEMBLER__
#define ENCLU_EENTER 2
#define ENCLU_ERESUME 3
#endif
#define OE_WORDSIZE 8
#define OE_OCALL_CODE 3

#if defined(__linux__)
#define oe_enter __morestack
#endif

#ifndef __ASSEMBLER__
typedef struct _oe_enclave oe_enclave_t;
#endif

#ifndef __ASSEMBLER__
void oe_enter(
    void* tcs,
    uint64_t aep,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave);

extern const uint64_t OE_AEP_ADDRESS;
#endif

#ifndef __ASSEMBLER__
void oe_enter_sim(
    void* tcs,
    uint64_t aep,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave);
#endif

#ifndef __ASSEMBLER__
int __oe_dispatch_ocall(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1_out,
    uint64_t* arg2_out,
    void* tcs,
    oe_enclave_t* enclave);
#endif

#ifndef __ASSEMBLER__
int __oe_host_stack_bridge(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1_out,
    uint64_t* arg2_out,
    void* tcs,
    oe_enclave_t* enclave,
    oe_ecall_context_t* ecall_context);
#endif

#ifndef __ASSEMBLER__
typedef struct _oe_host_ocall_frame
{
    uint64_t previous_rbp;
    uint64_t return_address;
} oe_host_ocall_frame_t;
#endif

#ifndef __ASSEMBLER__
uint32_t oe_push_enclave_instance(oe_enclave_t* enclave);
#endif

#ifndef __ASSEMBLER__
uint32_t oe_remove_enclave_instance(oe_enclave_t* enclave);
#endif

#ifndef __ASSEMBLER__
oe_enclave_t* oe_query_enclave_instance(void* tcs);
#endif
#endif /* _ASMDEFS_H */
