#ifndef _CONTEXT_H
#define _CONTEXT_H

#ifndef __ASSEMBLER__
#include <openenclave/defs.h>
#include <openenclave/types.h>
#include "sgxtypes.h"

// X87 and SSE data.
typedef struct _OE_BASIC_XSATE
{
    uint8_t     blob[512];
} __attribute__((aligned(16))) OE_BASIC_XSATE;

typedef struct _OE_CONTEXT
{
    // Flags.
    uint64_t    flags;

    // Integer registers.
    uint64_t    rax;
    uint64_t    rbx;
    uint64_t    rcx;
    uint64_t    rdx;

    uint64_t    rbp;
    uint64_t    rsp;

    uint64_t    rdi;
    uint64_t    rsi;

    uint64_t    r8;
    uint64_t    r9;
    uint64_t    r10;
    uint64_t    r11;
    uint64_t    r12;
    uint64_t    r13;
    uint64_t    r14;
    uint64_t    r15;

    uint64_t    rip;

    // Don't need to manipulate the segment registers directly. 
    // Ignore them: CS, DS, ES, SS, GS, and FS.

    // SSE control flags.
    uint32_t    mxcsr;

    // Basic XState.
    OE_BASIC_XSATE  basic_xstate;

    // Don't need to manipulate other XSTATE (AVE etc.). 
} OE_CONTEXT;

OE_CHECK_SIZE(sizeof(OE_CONTEXT), OE_CONTEXT_SIZE);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, flags), OE_CONTEXT_FLAGS);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rax), OE_CONTEXT_RAX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rbx), OE_CONTEXT_RBX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rcx), OE_CONTEXT_RCX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rdx), OE_CONTEXT_RDX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rbp), OE_CONTEXT_RBP);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rsp), OE_CONTEXT_RSP);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rdi), OE_CONTEXT_RDI);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rsi), OE_CONTEXT_RSI);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r8), OE_CONTEXT_R8);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r9), OE_CONTEXT_R9);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r10), OE_CONTEXT_R10);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r11), OE_CONTEXT_R11);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r12), OE_CONTEXT_R12);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r13), OE_CONTEXT_R13);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r14), OE_CONTEXT_R14);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, r15), OE_CONTEXT_R15);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, rip), OE_CONTEXT_RIP);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, mxcsr), OE_CONTEXT_MXCSR);
OE_CHECK_SIZE(OE_OFFSETOF(OE_CONTEXT, basic_xstate), OE_CONTEXT_FLOAT);

void OE_SnapCurrentContext(OE_CONTEXT * oe_context);
void OE_RestorePartialContext(OE_CONTEXT * oe_context);
void OE_ContinueExecution(OE_CONTEXT * oe_context);

typedef struct _OE_EXCEPTION_RECORD
{
    // Exception code.
    uint32_t    code;

    // Exception flags.
    uint32_t    flags;

    // Exception address.
    uint64_t    address;

    // Context.
    OE_CONTEXT  *context;
} OE_EXCEPTION_RECORD;

typedef uint64_t(*POE_VECTORED_EXCEPTION_HANDLER)(OE_EXCEPTION_RECORD *exceptionContext);
#endif // !__ASSEMBLER__ 

#endif /* _CONTEXT_H */