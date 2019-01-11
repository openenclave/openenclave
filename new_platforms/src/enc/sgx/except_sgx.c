/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include "oeshim_enc.h"
#include <sgx_trts.h>
#include <sgx_utils.h>
#include <sgx_trts_exception.h>

int oe_exception_handler(sgx_exception_info_t *info)
{
    oe_context_t context = { 0 };
    oe_exception_record_t record = { 0 };
    switch (info->exception_vector) {
    case SGX_EXCEPTION_VECTOR_DE: /* DIV and DIV instructions */
    case SGX_EXCEPTION_VECTOR_DB: /* For Intel use only */
        record.code = OE_EXCEPTION_DIVIDE_BY_ZERO;
        break;
    case SGX_EXCEPTION_VECTOR_BP: /* INT 3 instruction */
        record.code = OE_EXCEPTION_BREAKPOINT;
        break;
    case SGX_EXCEPTION_VECTOR_BR: /* BOUND instruction */
        record.code = OE_EXCEPTION_BOUND_OUT_OF_RANGE;
        break;
    case SGX_EXCEPTION_VECTOR_UD: /* UD2 instruction or reserved opcode */
        record.code = OE_EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    case SGX_EXCEPTION_VECTOR_MF: /* x87 FPU floating-point or WAIT/FWAIT instruction */
        record.code = OE_EXCEPTION_X87_FLOAT_POINT;
        break;
    case SGX_EXCEPTION_VECTOR_AC: /* Any data reference in memory */
        record.code = OE_EXCEPTION_ACCESS_VIOLATION;
                   // OE_EXCEPTION_PAGE_FAULT
                   // OE_EXCEPTION_MISALIGNMENT
        break;
    case SGX_EXCEPTION_VECTOR_XM: /* SSE/SSE2/SSE3 floating-point instruction */
        record.code = OE_EXCEPTION_SIMD_FLOAT_POINT;
        break;
    default:
        record.code = OE_EXCEPTION_UNKNOWN;
        break;
    }
    if (info->exception_type == SGX_EXCEPTION_HARDWARE) {
        record.flags |= OE_EXCEPTION_FLAGS_HARDWARE;
    } else if (info->exception_type == SGX_EXCEPTION_SOFTWARE) {
        record.flags |= OE_EXCEPTION_FLAGS_SOFTWARE;
    }
    record.context = &context;

    context.flags = record.flags;
#if defined (_M_X64) || defined (__x86_64__)
    record.address = info->cpu_context.rip;
    context.rax = info->cpu_context.rax;
    context.rbx = info->cpu_context.rbx;
    context.rcx = info->cpu_context.rcx;
    context.rdx = info->cpu_context.rdx;
    context.rbp = info->cpu_context.rbp;
    context.rsp = info->cpu_context.rsp;
    context.rdi = info->cpu_context.rdi;
    context.rsi = info->cpu_context.rsi;
    context.r8 = info->cpu_context.r8;
    context.r9 = info->cpu_context.r9;
    context.r10 = info->cpu_context.r10;
    context.r11 = info->cpu_context.r11;
    context.r12 = info->cpu_context.r12;
    context.r13 = info->cpu_context.r13;
    context.r14 = info->cpu_context.r14;
    context.r15 = info->cpu_context.r15;
    context.rip = info->cpu_context.rip;
    context.mxcsr = info->cpu_context.rflags;
    /* context.basic_xstate = ... */
#else
    record.address = info->cpu_context.eip;
    context.rax = info->cpu_context.eax;
    context.rbx = info->cpu_context.ebx;
    context.rcx = info->cpu_context.ecx;
    context.rdx = info->cpu_context.edx;
    context.rbp = info->cpu_context.ebp;
    context.rsp = info->cpu_context.esp;
    context.rdi = info->cpu_context.edi;
    context.rsi = info->cpu_context.esi;
    context.rip = info->cpu_context.eip;
    context.mxcsr = info->cpu_context.eflags;
    /* context.basic_xstate = ... */
#endif

    oe_exception_handler_entry* entry;
    for (entry = g_OEExceptionHandlerHead.next;
         entry != &g_OEExceptionHandlerHead;
         entry = entry->next) {
        uint64_t result = entry->handler(&record);
        if (result != 0) {
            return (int)result;
        }
    }
    return 0;
}

void* oe_register_exception_handler(void)
{
    return sgx_register_exception_handler(TRUE, oe_exception_handler);
}

int oe_unregister_exception_handler(void* handle)
{
    return sgx_unregister_exception_handler(handle);
}
