// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/sgxtypes.h>
#include "asmdefs.h"
#include "enclave.h"

// Define a variable with given name and bind it to the register with the
// corresponding name. This allows manipulating the register as a normal
// C variable. The variable and hence the register is also assigned the
// specified value.
#define OE_DEFINE_REGISTER(regname, value) \
    register uint64_t regname __asm__(#regname) = (uint64_t)(value)

#if _WIN32

// In x64 Windows ABI, the frame pointer can be any register and the frame
// pointer points to a constant location *within* the frame. In x64, the
// frame pointer points to the top of the frame. Windows debugger extensions
// for Open Enclave SDK require a linux-style frame pointer for the oe_enter
// function on the host-side.
#define OE_DEFINE_FRAME_POINTER(r, v) OE_DEFINE_REGISTER(r, v)

// As per Windows x64 ABI, the linux style frame pointer is -0x40 bytes
// from the address of the enclave parameter which is passed via the stack.
// Enclave parameter is the 7th parameter. Including the return-address, the
// Linux style frame-pointer is -(7+1)*8 = -64 = -0x40 bytes from the enclave
// parameter in the stack.
#define OE_FRAME_POINTER_VALUE ((uint64_t)&enclave - 0x40)
#define OE_FRAME_POINTER , "r"(rbp)

#elif __linux__

// The debugger requires a Linux x64 ABI frame pointer for stack walking.
// Therefore, this file must be compiled with -fno-omit-frame-pointer.
// Nothing else needs to be done and the macros below are noops.
#define OE_DEFINE_FRAME_POINTER(r, v) OE_UNUSED(v)
#define OE_FRAME_POINTER_VALUE 0
#define OE_FRAME_POINTER

#endif

// The following registers are inputs to ENCLU instruction. They are also
// clobbered. Hence marked as +r.
#define OE_ENCLU_REGISTERS \
    "+r"(rax), "+r"(rbx), "+r"(rcx), "+r"(rdi), "+r"(rsi), "+r"(r8)

// The following registers are clobbered by ENCLU.
// Only rbp and rsp are preserved.
#define OE_ENCLU_CLOBBERED_REGISTERS \
    "rdx", "r9", "r10", "r11", "r12", "r13", "r14", "r15"

/**
 * oe_enter Executes the ENCLU instruction and transfers control to the enclave.
 *
 * The ENCLU instruction has the following contract:
 * EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2, R8=eexit-frame) contract
 * Input:
 *       RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2, R8=eexit-frame
 *       RBP=Current host stack rbp,
 *       RSP=Current host stack sp.
 *       All other registers are NOT used/ignored.
 *  Output:
 *       RDI=ARG1OUT, RSI=ARG2OUT,
 *       RBP is not changed,
 *       RSP might be decreased because of host stack memory allocation.
 *       All other Registers are clobbered.
 */
OE_NEVER_INLINE
void oe_enter(
    void* tcs,
    uint64_t aep,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave)
{
    // The general purpose registers are preserved by the compiler.
    // The floating point state and the flags must be explicitly preserved.
    // The space for saving the floating-point state must be 16 byte aligned.
    OE_ALIGNED(16)
    uint64_t fx_state[64];

    oe_ocall_context_t eexit_frame;
    while (1)
    {
        // Define register bindings and initialize the registers.
        // On Windows, explicitly setup rbp as a Linux ABI style frame-pointer.
        // On Linux, the frame-pointer is set up by compiling the file with the
        // -fno-omit-frame-pointe flag.
        OE_DEFINE_REGISTER(rax, ENCLU_EENTER);
        OE_DEFINE_REGISTER(rbx, tcs);
        OE_DEFINE_REGISTER(rcx, aep);
        OE_DEFINE_REGISTER(rdi, arg1);
        OE_DEFINE_REGISTER(rsi, arg2);
        OE_DEFINE_REGISTER(r8, &eexit_frame);
        OE_DEFINE_FRAME_POINTER(rbp, OE_FRAME_POINTER_VALUE);

        asm volatile("fxsave %[fx_state] \n\t" // Save floating point state.
                     "pushfq \n\t"             // Save flags.
                     "enclu \n\t"
                     "popfq \n\t"               // Restore flags.
                     "fxrstor %[fx_state] \n\t" // Restore floating point state.
                     : OE_ENCLU_REGISTERS
                     : [fx_state] "m"(fx_state)OE_FRAME_POINTER
                     : OE_ENCLU_CLOBBERED_REGISTERS);

        // Update arg1 and arg2 with outputs returned by the enclave.
        arg1 = rdi;
        arg2 = rsi;

        // Make an OCALL if needed.
        oe_code_t code = oe_get_code_from_call_arg1(arg1);
        if (code == OE_CODE_OCALL)
        {
            __oe_host_stack_bridge(
                arg1, arg2, &arg1, &arg2, tcs, enclave, &eexit_frame);
        }
        else
            break;
    }

    *arg3 = arg1;
    *arg4 = arg2;
}

/**
 * oe_enter_sim Simulates the ENCLU instruction.
 *
 * See oe_enter above for ENCLU instruction's contract.
 * For simulation, the contract is modified as below:
 *  - rax is the CSSA which is always 0
 *  - rcx contains the return address instead of the AEP
 *  - The address of the enclave entry point is fetched from the tcs
 *    (offset 72) and the control is transferred to it via a jmp
 */
OE_NEVER_INLINE
void oe_enter_sim(
    void* tcs,
    uint64_t aep,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave)
{
    OE_UNUSED(aep);
    OE_ALIGNED(16)
    uint64_t fx_state[64];

    oe_ocall_context_t eexit_frame;
    while (1)
    {
        // Define register bindings and initialize the registers.
        // See oe_enter for ENCLU contract.
        OE_DEFINE_REGISTER(rax, 0 /* CSSA */);
        OE_DEFINE_REGISTER(rbx, tcs);
        OE_DEFINE_REGISTER(rcx, 0 /* filled in asm snippet */);
        OE_DEFINE_REGISTER(rdi, arg1);
        OE_DEFINE_REGISTER(rsi, arg2);
        OE_DEFINE_REGISTER(r8, &eexit_frame);
        OE_DEFINE_FRAME_POINTER(rbp, OE_FRAME_POINTER_VALUE);

        asm volatile("fxsave %[fx_state] \n\t"    // Save floating point state
                     "pushfq \n\t"                // Save flags
                     "lea 1f(%%rip), %%rcx \n\t"  // Load return address in rcx
                     "mov 72(%%rbx), %% rdx \n\t" // Load enclave entry point
                     "jmp *%%rdx  \n\t"           // Jump to enclave entry point
                     "1: \n\t"
                     "popfq \n\t"               // Restore flags
                     "fxrstor %[fx_state] \n\t" // Restore floating point state
                     : OE_ENCLU_REGISTERS
                     : [fx_state] "m"(fx_state)OE_FRAME_POINTER
                     : OE_ENCLU_CLOBBERED_REGISTERS);

        // Update arg1 and arg2 with outputs returned by the enclave.
        arg1 = rdi;
        arg2 = rsi;

        // Make an OCALL if needed.
        oe_code_t code = oe_get_code_from_call_arg1(arg1);
        if (code == OE_CODE_OCALL)
        {
            __oe_host_stack_bridge(
                arg1, arg2, &arg1, &arg2, tcs, enclave, &eexit_frame);
        }
        else
            break;
    }

    *arg3 = arg1;
    *arg4 = arg2;
}
