// Copyright (c) Open Enclave SDK contributors.
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
#define TD_FROM_TCS (5 * PAGE_SIZE)

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
#define td_host_ecall_context (td_simulate + 8)
#define td_host_previous_ecall_context (td_host_ecall_context + 8)

#define oe_exit_enclave __morestack
#ifndef __ASSEMBLER__
/* This function exits the enclave by initiating the ENCLU-EEXIT instruction.
 * It should not be confused with oe_exit(), which maps to the standard-C
 * exit() function defined in <openenclave/corelibc/stdlib.h>.
 */
void oe_exit_enclave(uint64_t arg1, uint64_t arg2) OE_NO_RETURN;

/* This is the actual implementation of eexit */
void oe_asm_exit(uint64_t arg1, uint64_t arg2) OE_NO_RETURN;
#endif

#ifndef __ASSEMBLER__
void __oe_handle_main(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t cssa,
    void* tcs,
    uint64_t* output_arg1,
    uint64_t* output_arg2);

void oe_exception_dispatcher(void* context);
#endif

#endif /* _ASMDEFS_H */
