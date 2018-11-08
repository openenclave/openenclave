// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ASMDEFS_H
#define _ASMDEFS_H

#ifndef __ASSEMBLER__
#include <openenclave/enclave.h>
#endif

#define ENCLU_EGETKEY 1
#define ENCLU_EENTER 2
#define ENCLU_EEXIT 4

#define PAGE_SIZE 4096
#define STATIC_STACK_SIZE 8 * 100
#define OE_WORD_SIZE 8

#define CODE_ERET 0x200000000

/* Use GS register if this flag is set */
#ifdef __ASSEMBLER__
#define OE_ARG_FLAG_GS 0x0001
#endif

/* Offsets into td_t structure */
#define td_self_addr 0
#define td_last_sp 8
#define td_magic 168
#define td_depth (td_magic + 8)
#define td_host_rcx (td_depth + 8)
#define td_host_rsp (td_host_rcx + 8)
#define td_host_rbp (td_host_rsp + 8)
#define td_host_previous_rsp (td_host_rbp + 8)
#define td_host_previous_rbp (td_host_previous_rsp + 8)
#define td_oret_func (td_host_previous_rbp + 8)
#define td_oret_arg (td_oret_func + 8)
#define td_callsites (td_oret_arg + 8)
#define td_simulate (td_callsites + 8)

#if defined(__linux__)
#define oe_exit __morestack
#endif /* defined(__linux__) */

#ifndef __ASSEMBLER__
void oe_exit(uint64_t arg1, uint64_t arg2);
#endif

#ifndef __ASSEMBLER__

typedef struct _oe_ecall_enc_args_t
{
    uint64_t cssa;
    void* tcs;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg1_out;
    uint64_t arg2_out;
} oe_ecall_enc_args_t;

void __oe_handle_main(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t cssa,
    void* tcs,
    uint64_t* output_arg1,
    uint64_t* output_arg2);

void __oe_handle_main_wrap(oe_ecall_enc_args_t* ecall_args);

void oe_exception_dispatcher(void* context);

#endif /* __ASSEMBLER__ */

#ifndef __ASSEMBLER__
void oe_notify_nested_exit_start(
    uint64_t arg1,
    oe_ocall_context_t* ocall_context);
#endif

#endif /* _ASMDEFS_H */
