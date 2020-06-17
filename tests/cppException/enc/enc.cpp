// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include "cppException_t.h"

bool TestCppException();

int test(void)
{
    if (!TestCppException())
    {
        oe_host_printf("Failed to test cpp exception.\n");
        return -1;
    }

    oe_host_printf("Cpp exception tests passed!\n");

    return 0;
}

bool ExceptionInUnwind();
bool ExceptionSpecification();
bool UnhandledException();
int test_unhandled_exception(unhandled_exception_func_num func_num)
{
    oe_host_printf("This test will crash the enclave.\n");
    switch (func_num)
    {
        case EXCEPTION_SPECIFICATION:
            ExceptionSpecification();
            break;

        case EXCEPTION_IN_UNWIND:
            ExceptionInUnwind();
            break;

        case UNHANDLED_EXCEPTION:
            UnhandledException();
            break;

        default:
            break;
    }

    oe_host_printf("Error: unreachable code is reached.\n");
    return -1;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    64,   /* NumStackPages */
    2);   /* NumTCS */
