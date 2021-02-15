// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ABI_UTILS_H
#define _OE_ABI_UTILS_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN
// oe_is_avx_enabled is an internal variable setup and used by OE SDK host
// runtime. It is OK for the abi test to depend on it do selectively perform
// checks.
extern bool oe_is_avx_enabled;
OE_EXTERNC_END

// User-mode settable RFLAGS that are not commonly modified and usually
// survive function calls: IF:9, NT:14
#define TEST_RFLAGS 0x4200

// RFLAGS value to clear TEST_RFLAGS: IF:9
// IF is kernel-managed and usually set, so restore it if changed
#define INIT_RFLAGS 0x200

// Set FTZ, Truncation RC and DAZ, clear all exception masks
#define TEST_MXCSR 0xE040

// Initial MXCSR value as defined by Linux/Window ABIs
#define INIT_MXCSR 0x1F80

// Set RC to RNE, PC to SP, clear all exception masks (11 00 01 000000)
#define TEST_FCW 0xC40

// Initial MXCSR value as defined by Linux/Window ABIs
#define INIT_FCW 0x37F

// Constant for expected result of enclave_check_abi function
#define EXPECTED_CHECK_ABI_RETURN_VALUE 42.0

typedef struct _windows_abi_state
{
    uint64_t rsi;
    uint64_t rdi;
    uint8_t xmm6[16];
    uint8_t xmm7[16];
    uint8_t xmm8[16];
    uint8_t xmm9[16];
    uint8_t xmm10[16];
    uint8_t xmm11[16];
    uint8_t xmm12[16];
    uint8_t xmm13[16];
    uint8_t xmm14[16];
    uint8_t xmm15[16];
} windows_abi_state_t;

typedef struct _abi_state
{
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    uint64_t flags;
    uint32_t mxcsr;
    uint16_t fcw;
    uint16_t padding;

    windows_abi_state_t win_abi;
} abi_state_t;

OE_ALWAYS_INLINE void set_test_xmm_state(void)
{
    static const uint8_t test_xmm[16] = {0xBE,
                                         0xEF,
                                         0xCA,
                                         0xFE,
                                         0xBE,
                                         0xEF,
                                         0xCA,
                                         0xFE,
                                         0xBE,
                                         0xEF,
                                         0xCA,
                                         0xFE,
                                         0xBE,
                                         0xEF,
                                         0xCA,
                                         0xFE};

    if (oe_is_avx_enabled)
        asm("vmovdqu %0, %%xmm6;"
            "vmovdqu %0, %%xmm7;"
            "vmovdqu %0, %%xmm8;"
            "vmovdqu %0, %%xmm9;"
            "vmovdqu %0, %%xmm10;"
            "vmovdqu %0, %%xmm11;"
            "vmovdqu %0, %%xmm12;"
            "vmovdqu %0, %%xmm13;"
            "vmovdqu %0, %%xmm14;"
            "vmovdqu %0, %%xmm15;"
            :
            : "m"(test_xmm)
            : "xmm6",
              "xmm7",
              "xmm8",
              "xmm9",
              "xmm10",
              "xmm11",
              "xmm12",
              "xmm13",
              "xmm14",
              "xmm15");
}

OE_ALWAYS_INLINE void set_test_abi_state(void)
{
    uint64_t test_flags = TEST_RFLAGS;
    uint32_t test_mxcsr = TEST_MXCSR;
    uint16_t test_fcw = TEST_FCW;

    asm("pushq %0;"
        "popfq;"
        "ldmxcsr %1;"
        "fldcw %2;" ::"m"(test_flags),
        "m"(test_mxcsr),
        "m"(test_fcw));
}

OE_ALWAYS_INLINE void reset_test_abi_state(void)
{
    uint64_t test_flags = INIT_RFLAGS;
    uint32_t test_mxcsr = INIT_MXCSR;
    uint16_t test_fcw = INIT_FCW;

    asm("pushq %0;"
        "popfq;"
        "ldmxcsr %1;"
        "fldcw %2;" ::"m"(test_flags),
        "m"(test_mxcsr),
        "m"(test_fcw));
}

OE_ALWAYS_INLINE void read_abi_state(abi_state_t* state)
{
    if (oe_is_avx_enabled)
        asm("movq %%rbx, (%0);"
            "movq %%rbp, 8(%0);"
            "movq %%rsp, 16(%0);"
            "movq %%r12, 24(%0);"
            "movq %%r13, 32(%0);"
            "movq %%r14, 40(%0);"
            "movq %%r15, 48(%0);"
            "pushfq;"
            "popq 56(%0);"
            "stmxcsr 64(%0);"
            "fstcw 68(%0);"
            "movq    %%rsi, (%1);"
            "movq    %%rdi, 8(%1);"
            "vmovdqu %%xmm6, 16(%1);"
            "vmovdqu %%xmm7, 32(%1);"
            "vmovdqu %%xmm8, 48(%1);"
            "vmovdqu %%xmm9, 64(%1);"
            "vmovdqu %%xmm10, 80(%1);"
            "vmovdqu %%xmm11, 96(%1);"
            "vmovdqu %%xmm12, 112(%1);"
            "vmovdqu %%xmm13, 128(%1);"
            "vmovdqu %%xmm14, 144(%1);"
            "vmovdqu %%xmm15, 160(%1);"
            :
            : "r"(state), "r"(&state->win_abi));
}

OE_ALWAYS_INLINE bool is_same_abi_state(abi_state_t* a, abi_state_t* b)
{
    return (
        (a->rbx == b->rbx) && (a->rbp == b->rbp) &&
#ifndef GCC_RELEASE
        /* On GCC Release builds (Clang or Debug builds work),
         * the compiler optimization doesn't treat the always inlined
         * read_abi_state as a boundary and only restores RSP prior to
         * next function call, so RSP right before and after oe_enter
         * can have different values. oe_enter itself before and after ENCLU
         * does preserve the RSP, by manual debugging inspection, so this
         * is a test limitation. */
        (a->rsp == b->rsp) &&
#endif
        (a->r12 == b->r12) && (a->r13 == b->r13) && (a->r14 == b->r14) &&
        (a->r15 == b->r15) &&

        /* RFLAGS are generally volatile, only check stable test bits */
        ((a->flags & TEST_RFLAGS) == (b->flags & TEST_RFLAGS)) &&

        (a->mxcsr == b->mxcsr) && (a->fcw == b->fcw)
#if defined(_WIN32)
        && (memcmp(
                (char*)&a->win_abi,
                (char*)&b->win_abi,
                sizeof(windows_abi_state_t)) == 0)
#endif
    );
}

#endif //_OE_ABI_UTILS_H
