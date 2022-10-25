// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../vdso.h"
#include <openenclave/host.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/ecall_context.h>
#include <openenclave/internal/trace.h>
#include <signal.h>
#include <sys/auxv.h>
#include "../asmdefs.h"
#include "../enclave.h"
#include "../exception.h"
#include "sgx.h" // Linux kernel header

/* Define a variable with given name and bind it to the register with the
 * corresponding name. This allows manipulating the register as a normal
 * C variable. The variable and hence the register is also assigned the
 * specified value. */
#define OE_DEFINE_REGISTER(regname, value) \
    register uint64_t regname __asm__(#regname) = (uint64_t)(value)

/* The following registers are clobbered by the vDSO call.
 * Only rbp and rsp are preserved on return from the vDSO call. */
#define OE_VDSO_CLOBBERED_REGISTERS                                           \
    "r10", "r11", "r12", "r13", "r14", "r15", "xmm6", "xmm7", "xmm8", "xmm9", \
        "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"

/* The following registers are inputs to the vDSO call. They are also
 * clobbered and hence are marked as +r. */
#define OE_VDSO_REGISTERS                                             \
    "+r"(rax), "+r"(rbx), "+r"(rcx), "+r"(rdi), "+r"(rsi), "+r"(rdx), \
        "+r"(r8), "+r"(r9)

/* Intel SGX definitions */
#define SGX_EXCEPTION_VECTOR_GENERAL_PROTECTION 13
#define SGX_EXCEPTION_VECTOR_PAGE_FAULT 14

extern bool oe_is_avx_enabled;

static elf64_sym_t _sgx_enter_enclave_sym;
static vdso_sgx_enter_enclave_t _vdso_sgx_enter_enclave;

oe_result_t oe_sgx_initialize_vdso(void)
{
    oe_result_t result = OE_NOT_FOUND;
    void* sgx_vdso_base = (void*)getauxval(AT_SYSINFO_EHDR);

    if (!sgx_vdso_base)
        goto done;

    if (elf64_find_dynamic_symbol_by_name_with_header(
            (const elf64_ehdr_t*)sgx_vdso_base,
            "__vdso_sgx_enter_enclave",
            &_sgx_enter_enclave_sym) != 0)
        goto done;

    _vdso_sgx_enter_enclave = (vdso_sgx_enter_enclave_t)(
        (uint64_t)sgx_vdso_base + _sgx_enter_enclave_sym.st_value);

    result = OE_OK;

done:
    if (result == OE_OK)
        OE_TRACE_INFO("vDSO symbols found. Opt into oe_vdso_enter.");
    else
        OE_TRACE_INFO("vDSO symbols not found. Fallback to regular oe_enter "
                      "implementation.");

    return result;
}

typedef struct _oe_vdso_return_args
{
    uint64_t rdi;
    uint64_t rsi;
} oe_vdso_return_args_t;

static int oe_vdso_user_handler(
    long rdi,
    long rsi,
    long rdx,
    long rsp,
    long r8,
    long r9,
    struct sgx_enclave_run* run)
{
    oe_vdso_return_args_t* return_args = NULL;
    uint64_t arg1 = (uint64_t)rdi;
    uint64_t arg2 = (uint64_t)rsi;
    int result = 0;

    OE_UNUSED(rdx);
    OE_UNUSED(rsp);
    OE_UNUSED(r8);
    OE_UNUSED(r9);

    if (!run)
    {
        result = -1;
        goto done;
    }

    return_args = (oe_vdso_return_args_t*)run->user_data;

    switch (run->function)
    {
        case ENCLU_EENTER:
            /* Unexpected case (e.g., the enclave loses EPC context
             * because of power events). Return failing value. */
            result = -1;
            break;
        case ENCLU_EEXIT:
        {
            /* Regular exit (the enclave finishes an ECALL or makes an
             * OCALL). Return zero.
             * Note that an alternative implementation is returning
             * ENCLU_EENTER. However, doing so requires setting up
             * the input parameters into corresponding registers (e.g.,
             * rdi, rsi, and rdx) and ensuring the compiler to preserve
             * these registers until the function returns. Instead,
             * we return zero to avoid dealing with such complexities
             * and also to use similar implementation as regular enter. */
            return_args->rdi = arg1;
            return_args->rsi = arg2;
            result = 0;
            break;
        }
        case ENCLU_ERESUME:
        {
            /* Hardware exceptions occur */

            oe_host_exception_context_t host_context = {0};
            uint64_t action = 0;

            host_context.rax = ENCLU_ERESUME;
            host_context.rbx = run->tcs;

            /* Pass down the faulting address when the exception type is #PF or
             * #GP to align with the behavior of #PF simulation when vDSO is not
             * used */
            if (run->exception_vector ==
                    SGX_EXCEPTION_VECTOR_GENERAL_PROTECTION ||
                run->exception_vector == SGX_EXCEPTION_VECTOR_PAGE_FAULT)
            {
                /* The exception_addr will have lower 12 bits cleared by the
                 * SGX hardware for an enclave faulting access (same as si_addr
                 * in signal handler). */
                host_context.faulting_address = run->exception_addr;
                host_context.signal_number = SIGSEGV;
            }

            /* AEP is assigned by vDSO implementation */

            OE_TRACE_INFO("vDSO: exception occurred");

            action = oe_host_handle_exception(&host_context);
            if (action == OE_SGX_EXCEPTION_ENCLAVE_HANDLED)
                result = ENCLU_ERESUME;
            else
            {
                /* Should always be this case */
                if (action == OE_SGX_EXCEPTION_ENCLAVE_NOT_HANDLED)
                    OE_TRACE_ERROR(
                        "Unhandled in-enclave exception. To get more "
                        "information, configure the enclave with "
                        "CapturePFGPExceptions=1 and enable the in-enclave "
                        "logging.");
                result = -1;
            }

            break;
        }
    }

done:
    /* If the result <= 0, the value will be forwared as the return
     * value of _vdso_sgx_enter_enclave. Otherwise, _vdso_sgx_enter_enclave
     * will invoke the ENCLU[result] instead of returning to the caller. */
    return result;
}

/* The function should never be inline to preserve the stack frame. */
OE_NEVER_INLINE
oe_result_t oe_vdso_enter(
    void* tcs,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave)
{
    oe_ecall_context_t ecall_context = {0};
    oe_result_t result = OE_UNEXPECTED;
    struct sgx_enclave_run run = {0};
    oe_vdso_return_args_t return_args = {0};
    int return_value = 0;
    uint32_t mxcsr = 0;
    uint16_t fcw = 0;

    oe_setup_ecall_context(&ecall_context);

    run.tcs = (uint64_t)tcs;
    run.user_handler = (uint64_t)oe_vdso_user_handler;
    run.user_data = (uint64_t)&return_args;

    while (1)
    {
        /* Compiler will usually handle this on exiting a function that uses
         * AVX, but we need to avoid the AVX-SSE transition penalty here
         * manually as part of the transition to enclave. See
         * https://software.intel.com/content/www/us/en/develop/articles
         * /avoiding-avx-sse-transition-penalties.html */
        if (oe_is_avx_enabled)
            OE_VZEROUPPER;

        /* Define register bindings and initialize the registers. */
        OE_DEFINE_REGISTER(rax, _vdso_sgx_enter_enclave);
        OE_DEFINE_REGISTER(rbx, &run);
        OE_DEFINE_REGISTER(rcx, ENCLU_EENTER);
        OE_DEFINE_REGISTER(rdx, &ecall_context);
        OE_DEFINE_REGISTER(rdi, arg1);
        OE_DEFINE_REGISTER(rsi, arg2);
        OE_DEFINE_REGISTER(r8, 0);
        OE_DEFINE_REGISTER(r9, 0);

        /* Save and restore MXCSR, x87 control word, RFLAGS, and non-volatile
         * registers (excpet for RSP and RBP that are expected to be preserved)
         * before and after the vDSO call conform the Linux x64 ABI */
        asm volatile(
            "stmxcsr %[mxcsr] \n\t" // Save MXCSR
            "fstcw %[fcw] \n\t"     // Save x87 control word
            "pushfq \n\t"           // Save RFLAGS
            "pushq %%rbx \n\t"      // Pass 7th argument (run) via stack
            "call *%%rax \n\t"      // Invoke _vdso_sgx_enter_enclave
            "popq %%rbx \n\t"       // Restore the stack
            "popfq \n\t"            // Restore RFLAGS
            "mov %%eax, %[return_value] \n\t" // Get 32-bit return value
            "fldcw %[fcw] \n\t"               // Restore x87 control word
            "ldmxcsr %[mxcsr] \n\t"           // Restore MXCSR
            : OE_VDSO_REGISTERS, [return_value] "=m"(return_value)
            : [fcw] "m"(fcw), [mxcsr] "m"(mxcsr)
            : OE_VDSO_CLOBBERED_REGISTERS);

        if (return_value < 0)
            OE_RAISE(OE_FAILURE);

        /* Update arg1 and arg2 with outputs returned by the enclave */
        arg1 = return_args.rdi;
        arg2 = return_args.rsi;

        /* Make an OCALL if needed */
        oe_code_t code = oe_get_code_from_call_arg1(arg1);
        if (code == OE_CODE_OCALL)
        {
            __oe_host_stack_bridge(
                arg1, arg2, &arg1, &arg2, tcs, enclave, &ecall_context);
        }
        else
            break;
    }

    *arg3 = arg1;
    *arg4 = arg2;

    result = OE_OK;

done:
    return result;
}
