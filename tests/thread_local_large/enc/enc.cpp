// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>
#include <array>
#include <cstdint>
#include "thread_local_large_t.h"

using namespace std;

void enc_test()
{
    static thread_local array<uint8_t, 9000> a;
    for (auto& x : a)
    {
        OE_TEST(x == 0);
        x = 2;
    }

    // Perform an ocall.
    host_nop();

    // Expect that TLS is the same as before the ocall.
    for (const auto x : a)
        OE_TEST(x == 2);
}

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* Debug */
    64,   /* NumHeapPages */
    16,   /* NumStackPages */
    1);   /* NumTCS */
