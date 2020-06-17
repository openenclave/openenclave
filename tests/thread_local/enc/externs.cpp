// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <random>
#include "visibility.h"

VISIBILITY_SPEC thread_local std::random_device g_rd;
VISIBILITY_SPEC thread_local std::mt19937 g_mt(g_rd());
VISIBILITY_SPEC thread_local std::uniform_real_distribution<double> g_dist(
    1,
    100);

// The following behavior has been observed about this enclave:
// In release mode, both .tdata and .tbss have the same alignment (2**4).
// In debug mode, .tdata has alignment 2**4 whereas .tbss has alignment 2**3.
