// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Include the trait regression before any other C++ library headers so that
// its forced-fallback macro takes effect on Clang.
#define main run_regression
#include REGRESSION_SOURCE
#undef main

#include <cstdio>
#include <cstdlib>
#include "helloworld_t.h"

extern "C" void enclave_helloworld()
{
    const int result = run_regression();
    if (result != 0)
    {
        std::printf("LIBCXX_CONSUMER_FAIL: %d\n", result);
        std::abort();
    }
    std::puts("LIBCXX_CONSUMER_PASS");
}
