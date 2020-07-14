// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <random>
#include <set>
#include <thread>
#include "no_tdata_t.h"

// The following thread local declaration causes
// the linker to create only a .tbss section and
// no .tdata section. Additionally, it sets
// the program header's rva to point to the .tbss
// section, but sets the program header's size to
// be zero. This test locks down that we are
// able to load these types of enclaves.
struct foo
{
    uint64_t bar;
    void* ook;
};

static __thread struct foo _local_foo;

void enc_set_value(uint64_t value)
{
    _local_foo.bar = value;
    _local_foo.ook = NULL;
}

uint64_t enc_get_value()
{
    return _local_foo.bar;
}

#define NUM_TCS 16

OE_SET_ENCLAVE_SGX(
    0,                             /* ProductID */
    0,                             /* SecurityVersion */
    true,                          /* Debug */
    OE_TEST_MT_HEAP_SIZE(NUM_TCS), /* NumHeapPages */
    16,                            /* NumStackPages */
    NUM_TCS);                      /* NumTCS */
