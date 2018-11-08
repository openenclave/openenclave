// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ASMDEFS_H
#define _ASMDEFS_H

#ifndef __ASSEMBLER__
#include <openenclave/bits/types.h>
#include <openenclave/internal/context.h>
#include <stdint.h>
#endif

#ifdef __ASSEMBLER__
#define ENCLU_EENTER 2
#define ENCLU_ERESUME 3
#endif

#define ThreadBinding_tcs 0
#define OE_WORDSIZE 8
#define OE_OCALL_CODE 3

#if defined(__linux__)
#define oe_enter __morestack
#endif

#ifndef __ASSEMBLER__
typedef struct _oe_enclave oe_enclave_t;

typedef struct _oe_ecall_args_t
{
    void* tcs;
    oe_enclave_t* enclave;
    void (*aep)(void);
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg1_out;
    uint64_t arg2_out;
} oe_ecall_args_t;

#if defined(__linux__)

void oe_enter(
    void* tcs,
    void (*aep)(void),
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave);

#elif defined(_WIN32)

void oe_enter(oe_ecall_args_t* ecall_args);

#else

#error("unsupported");

#endif

void OE_AEP(void);

#endif /* __ASSEMBLER__ */

#define ECALL_ARG_TCS 0x0
#define ECALL_ARG_ENCLAVE 0x8
#define ECALL_ARG_AEP 0x10
#define ECALL_ARG_ARG1 0x18
#define ECALL_ARG_ARG2 0x20
#define ECALL_ARG_ARG1_OUT 0x28
#define ECALL_ARG_ARG2_OUT 0x30

#ifndef __ASSEMBLER__

OE_STATIC_ASSERT(ECALL_ARG_TCS == OE_OFFSETOF(oe_ecall_args_t, tcs));
OE_STATIC_ASSERT(ECALL_ARG_ARG1 == OE_OFFSETOF(oe_ecall_args_t, arg1));
OE_STATIC_ASSERT(ECALL_ARG_ARG2 == OE_OFFSETOF(oe_ecall_args_t, arg2));
OE_STATIC_ASSERT(ECALL_ARG_ARG1_OUT == OE_OFFSETOF(oe_ecall_args_t, arg1_out));
OE_STATIC_ASSERT(ECALL_ARG_ARG2_OUT == OE_OFFSETOF(oe_ecall_args_t, arg2_out));
OE_STATIC_ASSERT(ECALL_ARG_ENCLAVE == OE_OFFSETOF(oe_ecall_args_t, enclave));

#endif /* __ASSEMBLER__ */

#ifndef __ASSEMBLER__

void oe_enter_sim(
    void* tcs,
    void (*aep)(void),
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave);
#endif

#ifndef __ASSEMBLER__

#if defined(__linux__)

int __oe_dispatch_ocall(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1_out,
    uint64_t* arg2_out,
    void* tcs,
    oe_enclave_t* enclave);

#elif defined(_WIN32)

int __oe_dispatch_ocall(oe_ecall_args_t* ecall_args);

#else

#error("unsupported");

#endif /* defined(__linux__) */

#endif /* __ASSEMBLER__ */

#ifndef __ASSEMBLER__
int _oe_host_stack_bridge(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1_out,
    uint64_t* arg2_out,
    void* tcs,
    void* rsp);
#endif

#ifndef __ASSEMBLER__
typedef struct _oe_host_ocall_frame
{
    uint64_t previous_rbp;
    uint64_t return_address;
} oe_host_ocall_frame_t;
#endif

#ifndef __ASSEMBLER__
void oe_notify_ocall_start(oe_host_ocall_frame_t* frame_pointer, void* tcs);
#endif

#ifndef __ASSEMBLER__
void oe_notify_ocall_end(oe_host_ocall_frame_t* frame_pointer, void* tcs);
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
