// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CALLS_H
#define _OE_CALLS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cpuid.h>
#include "sgxtypes.h"

#define __OE_ECALL_BASE ((int)0x00FFFFFF)
#define __OE_OCALL_BASE ((int)0x00FFFFFF)

#define OE_MAX_ECALLS 1024
#define OE_MAX_OCALLS 1024

OE_EXTERNC_BEGIN

typedef struct _oe_enclave oe_enclave_t;

typedef void (*oe_ecall_function)(uint64_t argIn, uint64_t* argOut);

typedef void (*oe_ocall_function)(uint64_t argIn, uint64_t* argOut);

/*
**==============================================================================
**
** The flags parameter for oe_ocall()
**
** Flags stack with the ones on the current thread (i.e., are or'd together)
** for the duration of the ocall.
**
**==============================================================================
*/

/* Disallow OCALLs to call back into enclave with an ECALL */
#define OE_OCALL_FLAG_NOT_REENTRANT (1u << 0)

/*
**==============================================================================
**
** oe_code_t
**
**     The code parameter for oe_ecall() and oe_ocall()
**
**==============================================================================
*/

typedef enum _oe_code {
    OE_CODE_NONE = 0,
    OE_CODE_ECALL = 1,
    OE_CODE_ERET = 2,
    OE_CODE_OCALL = 3,
    OE_CODE_ORET = 4
} oe_code_t;

/*
**==============================================================================
**
** oe_func_t
**
**     The func parameter for oe_ecall() and oe_ocall()
**
**==============================================================================
*/

/* The first 65535 (0xffff) numbers are reserved for user defined calls */
#define OE_FUNC_BASE ((uint32_t)0x00010000)

typedef enum _oe_func {
    OE_FUNC_DESTRUCTOR = OE_FUNC_BASE + 0,
    OE_FUNC_INIT_ENCLAVE = OE_FUNC_BASE + 1,
    OE_FUNC_CALL_ENCLAVE = OE_FUNC_BASE + 2,
    OE_FUNC_CALL_HOST = OE_FUNC_BASE + 3,
    OE_FUNC_INIT_QUOTE = OE_FUNC_BASE + 4,
    OE_FUNC_GET_REPORT = OE_FUNC_BASE + 5,
    OE_FUNC_GET_QE_TARGET_INFO = OE_FUNC_BASE + 6,
    OE_FUNC_GET_QUOTE = OE_FUNC_BASE + 7,
    OE_FUNC_THREAD_WAKE = OE_FUNC_BASE + 8,
    OE_FUNC_THREAD_WAIT = OE_FUNC_BASE + 9,
    OE_FUNC_THREAD_WAKE_WAIT = OE_FUNC_BASE + 10,
    OE_FUNC_MALLOC = OE_FUNC_BASE + 11,
    OE_FUNC_REALLOC = OE_FUNC_BASE + 12,
    OE_FUNC_FREE = OE_FUNC_BASE + 13,
    OE_FUNC_PUTS = OE_FUNC_BASE + 14,
    OE_FUNC_PUTCHAR = OE_FUNC_BASE + 15,
    OE_FUNC_PRINT = OE_FUNC_BASE + 16,
    OE_FUNC_STRFTIME = OE_FUNC_BASE + 17,
    OE_FUNC_GETTIMEOFDAY = OE_FUNC_BASE + 18,
    OE_FUNC_CLOCK_GETTIME = OE_FUNC_BASE + 19,
    OE_FUNC_NANOSLEEP = OE_FUNC_BASE + 20,
    OE_FUNC_VIRTUAL_EXCEPTION_HANDLER = OE_FUNC_BASE + 21,
    OE_FUNC_VERIFY_REPORT = OE_FUNC_BASE + 22,
    /* Caution: always add new function numbers immediately before this line */
} oe_func_t;

#define OE_EXCEPTION_CONTINUE_SEARCH 0x0
#define OE_EXCEPTION_CONTINUE_EXECUTION 0xFFFFFFFF

/*
**==============================================================================
**
** oe_make_call_arg1()
**
**     Form the 'arg1' parameter to both oe_enter() and oe_exit(). This
**     parameter is a 64-bit integer that contains:
**
**         code -- indicating whether ECALL, OCALL, ERET, or ORET
**         func -- the number of the function being called
**         flags -- any bit flags
**
**==============================================================================
*/

OE_INLINE uint64_t
oe_make_call_arg1(oe_code_t code, oe_func_t func, uint16_t flags)
{
    /* [ FLAGS:16, CODE:16, FUNC:32 ] */
    return ((uint64_t)code << 48) | ((uint64_t)func << 16) | ((uint64_t)flags);
}

/*
**==============================================================================
**
** oe_get_code_from_call_arg1()
**
**==============================================================================
*/

OE_INLINE oe_code_t oe_get_code_from_call_arg1(uint64_t arg)
{
    return (oe_code_t)((0xFFFF000000000000 & arg) >> 48);
}

/*
**==============================================================================
**
** oe_get_func_from_call_arg1()
**
**==============================================================================
*/

OE_INLINE oe_func_t oe_get_func_from_call_arg1(uint64_t arg)
{
    return (oe_func_t)((0x0000FFFFFFFF0000 & arg) >> 16);
}

/*
**==============================================================================
**
** oe_get_flags_from_call_arg1()
**
**==============================================================================
*/

OE_INLINE uint16_t oe_get_flags_from_call_arg1(uint64_t arg)
{
    return (uint16_t)(0x000000000000FFFF & arg);
}

/*
**==============================================================================
**
** oe_call_enclave_args_t
**
**==============================================================================
*/

typedef void (*oe_enclave_func_t)(void* args);

typedef struct oe_call_enclave_args_t
{
    uint64_t func;
    uint64_t vaddr;
    void* args;
    oe_result_t result;
} oe_call_enclave_args_t;

/*
**==============================================================================
**
** oe_call_host_args_t
**
**==============================================================================
*/

typedef void (*oe_host_func_t)(void* args);

typedef struct oe_call_host_args_t
{
    void* args;
    oe_result_t result;
    OE_ZERO_SIZED_ARRAY char func[];
} oe_call_host_args_t;

/*
**==============================================================================
**
** oe_print_args_t
**
**     Print 'str' to stdout (device == 0) or stderr (device == 1).
**
**==============================================================================
*/

typedef struct _oe_print_args
{
    int device;
    char* str;
} oe_print_args_t;

/*
**==============================================================================
**
** oe_realloc_args_t
**
**     void* realloc(void* ptr, size_t size)
**
**==============================================================================
*/

typedef struct _oe_realloc_args
{
    void* ptr;
    size_t size;
} oe_realloc_args_t;

/*
**==============================================================================
**
** oe_init_enclave_args_t
**
**     Runtime state to initialize enclave state with, includes
**     - First 8 leaves of CPUID for enclave emulation
**
**==============================================================================
*/

typedef struct _oe_init_enclave_args
{
    uint32_t cpuidTable[OE_CPUID_LEAF_COUNT][OE_CPUID_REG_COUNT];
} oe_init_enclave_args_t;

/**
 * Perform a low-level enclave function call (ECALL).
 *
 * This function performs a low-level enclave function call by invoking the
 * function indicated by the **func** parameter. The enclave defines and
 * registers a corresponding function with the following signature.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut);
 *
 * The meaning of the **argIn** arg **argOut** parameters is defined by the
 * implementer of the function and either may be null.
 *
 * Open Enclave uses the low-level ECALL interface to implement internal calls,
 * used by oe_call_enclave() and oe_terminate_enclave(). Enclave application
 * developers are encouraged to use oe_call_enclave() instead.
 *
 * At the software layer, this function sends an **ECALL** message to the
 * enclave and waits for an **ERET** message. Note that the ECALL implementation
 * may call back into the host (an OCALL) before returning.
 *
 * At the hardware layer, this function executes the **ENCLU.EENTER**
 * instruction to enter the enclave. When the enclave returns from the ECALL,
 * it executes the **ENCLU.EEXIT** instruction exit the enclave and to resume
 * host execution.
 *
 * Note that the return value only indicates whether the ECALL was called and
 * not whether it was successful. The ECALL implementation must define its own
 * error reporting scheme based on its parameters.
 *
 * @param func The number of the function to be called.
 * @param argsIn The input argument passed to the function.
 * @param argOut The output argument passed back from the function.
 *
 * @retval OE_OK The function was successful.
 * @retval OE_FAILED The function failed.
 * @retval OE_INVALID_PARAMETER One or more parameters is invalid.
 * @retval OE_OUT_OF_THREADS No enclave threads are available to make the call.
 * @retval OE_UNEXPECTED An unexpected error occurred.
 *
 */
oe_result_t oe_ecall(
    oe_enclave_t* enclave,
    uint32_t func,
    uint64_t argIn,
    uint64_t* argOut);

/**
 * Perform a low-level host function call (OCALL).
 *
 * This function performs a low-level host function call by invoking the
 * function indicated by the **func** parameter. The host defines and
 * registers a corresponding function with the following signature.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut);
 *
 * The meaning of the **argIn** arg **argOut** parameters is defined by the
 * implementer of the function and either may be null.
 *
 * Open Enclave uses this interface to implement internal calls. Enclave
 * application developers are encouraged to use oe_call_host() instead.
 *
 * At the software layer, this function sends an **OCALL** message to the
 * enclave and waits for an **ORET** message. Note that the OCALL implementation
 * may call back into the enclave (an ECALL) before returning.
 *
 * At the hardware layer, this function executes the **ENCLU.EEXIT**
 * instruction to exit the enclave. When the host returns from the OCALL,
 * it executes the **ENCLU.EENTER** instruction to reenter the enclave and
 * resume execution.
 *
 * Note that the return value only indicates whether the OCALL was called
 * not whether it was successful. The ECALL implementation must define its own
 * error reporting scheme based on its parameters.
 *
 * @param func The number of the function to be called.
 * @param argIn The input argument passed to the function.
 * @param argOut The output argument passed back from the function.
 * @param ocall_flags Additional flags for the duration of this ocall, such as
 *              OE_OCALL_FLAG_NOT_REENTRANT.
 *
 * @retval OE_OK The function was successful.
 * @retval OE_FAILED The function failed.
 * @retval OE_INVALID_PARAMETER One or more parameters is invalid.
 * @retval OE_OUT_OF_THREADS No enclave threads are available to make the call.
 * @retval OE_UNEXPECTED An unexpected error occurred.
 *
 */
oe_result_t oe_ocall(
    uint32_t func,
    uint64_t argIn,
    uint64_t* argOut,
    uint32_t ocall_flags);
/**
 * Registers a low-level ECALL function.
 *
 * This function registers a low-level ECALL function that may be called
 * from the host by the **oe_ecall()** function. The registered function
 * has the following prototype.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut);
 *
 * This interface is intended mainly for internal use and developers are
 * encouraged to use the high-level interface instead.
 *
 * @param func The number of the function to be called.
 * @param ecall The address of the function to be called.
 *
 * @retval OE_OK The function was successful.
 * @retval OE_OUT_OF_RANGE The function number was greater than OE_MAX_ECALLS.
 * @retval OE_ALREADY_IN_USE The function number is already in use.
 *
 */
oe_result_t oe_register_ecall(uint32_t func, oe_ecall_function ecall);

/**
 * Registers a low-level OCALL function.
 *
 * TODO: Redesign this, this needs to be enclave-specific.
 *
 * This function registers a low-level OCALL function that may be called
 * from the enclave by the **oe_ocall()** function. The registered function
 * has the following prototype.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut);
 *
 * This interface is intended mainly for internal use and developers are
 * encouraged to use the high-level interface instead.
 *
 * @param func The number of the function to be called.
 * @param ocall The address of the function to be called.
 *
 * @retval OE_OK The function was successful.
 * @retval OE_OUT_OF_RANGE The function number was greater than OE_MAX_OCALLS.
 * @retval OE_ALREADY_IN_USE The function number is already in use.
 *
 */
oe_result_t oe_register_ocall(uint32_t func, oe_ocall_function ocall);

OE_EXTERNC_END

#endif /* _OE_CALLS_H */
