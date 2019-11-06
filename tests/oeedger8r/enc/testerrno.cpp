// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "all_t.h"

void test_errno_edl_ocalls()
{
    // Currently each ecall creates an new enclave thread and therefore all
    // thread-local variables are initialized to their default values. Thus
    // errno has default value 0. Also, ecalls currently do no transfer the host
    // errno value to the enclave.
    OE_TEST(errno == 0);

    errno = 0;
    OE_TEST(errno == 0);

    OE_TEST(ocall_errno() == OE_OK);
    OE_TEST(errno == 0x12345678);

    // Set host errno value using a function that does not propagate the value
    // back. Assert that the enclave errno value has not changed.
    OE_TEST(ocall_set_host_errno(0x1111) == OE_OK);
    OE_TEST(errno == 0x12345678);

    // Call a noop function to transfer current value of errno from host.
    OE_TEST(ocall_noop() == OE_OK);
    OE_TEST(errno == 0x1111);

    // Mashalling structs for ocalls marked with propagate_errno should have an
    // int _ocall_errno field. If not the case, the following code will not
    // compile.
    {
        ocall_errno_args_t args1;
        check_type<int>(args1._ocall_errno);

        ocall_noop_args_t args2;
        check_type<int>(args2._ocall_errno);
    }

    // Marshalling structs without the propagate_errno annotation will not have
    // the _ocall_errno field.
    assert_no_field__ocall_errno<ocall_set_host_errno_args_t>();

    printf("=== test_errno_edl_ocalls passed\n");
}
