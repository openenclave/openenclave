// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>
#include "enc2_t.h"

void enc_ecall1(MyStruct s)
{
    OE_TEST(s.x == 8);
    OE_TEST(s.y == 9);
    OE_TEST(host_ocall1(s) == OE_OK);
}

void enc_ecall2(MyUnion u)
{
    OE_TEST(u.y == 10);
    OE_TEST(host_ocall2(u) == OE_OK);
}

int enc_local_ecall2(int val)
{
    OE_TEST(val == 13);
    return 14;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    512,  /* NumHeapPages */
    512,  /* NumStackPages */
    1);   /* NumTCS */
