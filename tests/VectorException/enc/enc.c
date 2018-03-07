// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/atexit.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/jump.h>
#include <openenclave/bits/reloc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/enclave.h>
#include "../args.h"

// This function will generate the divide by zero function.
// The handler will catch this exception and fix it, and continue execute.
// It will return 0 if success.
int DivideByZeroExceptionFunction(void)
{
    int ret = 1;
    int s = 0;
    float f = 0;
    double d = 0;

    f = 0.31;
    d = 0.32;

    ret = ret / s;

    // Check if the float registers are recovered correctly after the exception
    // is handled.
    if (f < 0.309 || f > 0.321 || d < 0.319 || d > 0.321)
    {
        return ret;
    }

    return 0;
}

uint64_t TestDivideByZeroHandler(OE_EXCEPTION_RECORD* exception_record)
{
    if (exception_record->code != OE_EXCEPTION_DIVIDE_BY_ZERO)
    {
        return OE_EXCEPTION_CONTINUE_SEARCH;
    }

    // Skip the idiv instruction.
    exception_record->context->rip += 3;
    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

#define MAX_EXCEPTION_HANDLER_COUNT 64

#define PASSTHROUGH_EXCEPTION_HANDLER(__exception_hanlder_name_)              \
    uint64_t __exception_hanlder_name_(OE_EXCEPTION_RECORD* exception_record) \
    {                                                                         \
        return OE_EXCEPTION_CONTINUE_SEARCH;                                  \
    }

#define TEN_PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_) \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_0)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_1)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_2)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_3)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_4)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_5)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_6)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_7)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_8)     \
    PASSTHROUGH_EXCEPTION_HANDLER(__exception_handler_name_prefix_##_9)

// Define 64 pass through exception handlers.
TEN_PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler0)
TEN_PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler1)
TEN_PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler2)
TEN_PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler3)
TEN_PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler4)
TEN_PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler5)
PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler6_0)
PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler6_2)
PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler6_1)
PASSTHROUGH_EXCEPTION_HANDLER(TestPassThroughHandler6_3)

#define TEN_EXCEPTION_HANDLER_POINTERS(__exception_handler_name_prefix_) \
    __exception_handler_name_prefix_##_0,                                \
        __exception_handler_name_prefix_##_1,                            \
        __exception_handler_name_prefix_##_2,                            \
        __exception_handler_name_prefix_##_3,                            \
        __exception_handler_name_prefix_##_4,                            \
        __exception_handler_name_prefix_##_5,                            \
        __exception_handler_name_prefix_##_6,                            \
        __exception_handler_name_prefix_##_7,                            \
        __exception_handler_name_prefix_##_8,                            \
        __exception_handler_name_prefix_##_9,

static POE_VECTORED_EXCEPTION_HANDLER
    g_test_pass_through_handlers[MAX_EXCEPTION_HANDLER_COUNT] = {
        TEN_EXCEPTION_HANDLER_POINTERS(TestPassThroughHandler0)
            TEN_EXCEPTION_HANDLER_POINTERS(TestPassThroughHandler1)
                TEN_EXCEPTION_HANDLER_POINTERS(TestPassThroughHandler2)
                    TEN_EXCEPTION_HANDLER_POINTERS(TestPassThroughHandler3)
                        TEN_EXCEPTION_HANDLER_POINTERS(TestPassThroughHandler4)
                            TEN_EXCEPTION_HANDLER_POINTERS(
                                TestPassThroughHandler5)
                                TestPassThroughHandler6_0,
        TestPassThroughHandler6_1,
        TestPassThroughHandler6_2,
        TestPassThroughHandler6_3};

int VectorExceptionSetup()
{
    void* handler;
    uint64_t ret = -1;

    // Add one exception handler.
    handler = OE_AddVectoredExceptionHandler(0, TestDivideByZeroHandler);
    if (handler == NULL)
    {
        return ret;
    }

    // Remove the exception handler.
    ret = OE_RemoveVectoredExceptionHandler(handler);
    if (ret != 0)
    {
        return ret;
    }

    // Insert the exception handler to the front.
    handler = OE_AddVectoredExceptionHandler(1, TestDivideByZeroHandler);
    if (handler == NULL)
    {
        return ret;
    }

    // Remove the exception handler.
    ret = OE_RemoveVectoredExceptionHandler(handler);
    if (ret != 0)
    {
        return ret;
    }

    // Append one by one till reach the max.
    for (uint32_t i = 0; i < OE_COUNTOF(g_test_pass_through_handlers); i++)
    {
        handler =
            OE_AddVectoredExceptionHandler(0, g_test_pass_through_handlers[i]);
        if (handler == NULL)
        {
            return ret;
        }
    }

    // Can't add one more.
    handler = OE_AddVectoredExceptionHandler(0, TestDivideByZeroHandler);
    if (handler != NULL)
    {
        return ret;
    }

    // Remove all registered handlers.
    for (uint32_t i = 0; i < OE_COUNTOF(g_test_pass_through_handlers); i++)
    {
        ret =
            OE_RemoveVectoredExceptionHandler(g_test_pass_through_handlers[i]);
        if (ret != 0)
        {
            return ret;
        }
    }

    // Add handles to the front one by one till reach the max.
    for (uint32_t i = 0; i < OE_COUNTOF(g_test_pass_through_handlers); i++)
    {
        handler =
            OE_AddVectoredExceptionHandler(1, g_test_pass_through_handlers[i]);
        if (handler == NULL)
        {
            return ret;
        }
    }

    // Can't add one more.
    handler = OE_AddVectoredExceptionHandler(1, TestDivideByZeroHandler);
    if (handler != NULL)
    {
        return ret;
    }

    // Remove all registered handlers.
    for (uint32_t i = 0; i < OE_COUNTOF(g_test_pass_through_handlers); i++)
    {
        ret =
            OE_RemoveVectoredExceptionHandler(g_test_pass_through_handlers[i]);
        if (ret != 0)
        {
            return ret;
        }
    }

    // Add the test pass through handlers.
    for (uint32_t i = 0; i < OE_COUNTOF(g_test_pass_through_handlers) - 1; i++)
    {
        handler =
            OE_AddVectoredExceptionHandler(0, g_test_pass_through_handlers[i]);
        if (handler == NULL)
        {
            return ret;
        }
    }

    // Add the real handler to the end.
    handler = OE_AddVectoredExceptionHandler(0, TestDivideByZeroHandler);
    if (handler == NULL)
    {
        return ret;
    }

    ret = 0;
    return ret;
}

OE_ECALL void TestVectorException(void* args_)
{
    Args* args = (Args*)args_;
    args->ret = -1;

    if (!OE_IsOutsideEnclave(args, sizeof(Args)))
    {
        return;
    }

    if (VectorExceptionSetup() != 0)
    {
        return;
    }

    OE_HostPrintf(
        "TestVectorException: will generate a hardware exception "
        "inside enclave!\n");
    if (DivideByZeroExceptionFunction() != 0)
    {
        args->ret = -1;
        return;
    }

    OE_HostPrintf(
        "TestVectorException: hardware exception is handled correctly!\n");

    args->ret = 0;
    return;
}
