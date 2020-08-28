// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SGX_TYPES_H
#define _SGX_TYPES_H

#include <stdint.h>

#define ENCLU_ERESUME 3
#define TCS_HEADER_BYTE_SIZE 72
#define SGX_GPR_BYTE_SIZE 0xb8
#define ENCLU_INSTRUCTION 0xd7010f

typedef struct _sgx_tcs
{
    /* (0) enclave execution state (0=available, 1=unavailable) */
    uint64_t state;

    /* (8) thread's execution flags */
    uint64_t flags;

    /* (16) offset to the base of the State Save Area (SSA) stack */
    uint64_t ossa;

    /* (24) Current slot of an SSA frame */
    uint32_t cssa;

    /* (28) Number of available slots for SSA frames */
    uint32_t nssa;

    /* (32) entry point where control is transferred upon EENTER */
    uint64_t oentry;

    /* (40) Value of asynchronous exit pointer saved at EENTER time */
    uint64_t aep;

    /* (48) Added to enclave base address to get the FS segment address */
    uint64_t fsbase;

    /* (56) Added to enclave base address to get the GS segment address */
    uint64_t gsbase;

    /* (64) Size to become the new FS limit in 32-bit mode */
    uint32_t fslimit;

    /* (68) Size to become the new GS limit in 32-bit mode */
    uint32_t gslimit;

    /* (72) reserved */
    union {
        uint8_t reserved[4024];

        /* (72) Enclave's entry point (defaults to _start) */
        void (*entry)(void);
    } u;
} sgx_tcs_t;

typedef union {
    struct
    {
        uint32_t vector : 8;
        uint32_t exit_type : 3;
        uint32_t mbz : 20;
        uint32_t valid : 1;
    } as_fields;
    uint32_t as_uint32;
} sgx_exit_info;

typedef struct sgx_ssa_gpr_t
{
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
    uint64_t ursp;
    uint64_t urbp;
    sgx_exit_info exit_info;
    uint32_t reserved;
    uint64_t fs_base;
    uint64_t gs_base;
} sgx_ssa_gpr_t;

#endif // _SGX_TYPES_H
