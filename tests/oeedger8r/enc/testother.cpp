// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "other_t.h"

MyOther ecall_other(MyOther o)
{
    return MyOther{o.x + 1};
}

void test_other_edl_ocalls()
{
    MyOther ret;
    OE_TEST(ocall_other(&ret, {1}) == OE_OK);
    OE_TEST(ret.x == 2);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    256,  /* NumStackPages */
    4);   /* NumTCS */
