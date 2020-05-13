// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "other_u.h"

MyOther ocall_other(MyOther o)
{
    return MyOther{o.x + 1};
}

void test_other_edl_ecalls(oe_enclave_t* enclave)
{
    MyOther ret;
    OE_TEST(ecall_other(enclave, &ret, MyOther{1}) == OE_OK);
    OE_TEST(ret.x == 2);

    OE_TEST(ecall_other(enclave, &ret, MyOther{1}) == OE_OK);
    OE_TEST(ecall_shared_func(enclave) == OE_OK);
}
