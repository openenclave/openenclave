// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>

#include "alignment_t.h"

__attribute__((aligned(TBSS_ALIGNMENT))) __thread uint16_t tbss_var[1];

__attribute__((aligned(TDATA_ALIGNMENT))) __thread uint16_t tdata_var[1] = {
    12345};

uint64_t oe_sgx_get_thread_local_start_offset();

void enc_test_alignment()
{
    volatile uint16_t v1 = tbss_var[0];
    volatile uint16_t v2 = tdata_var[0];
    OE_TEST(v1 == 0);
    OE_TEST(v2 == 12345);

    uint64_t fs;
    asm volatile("mov %%fs:0, %0" : "=r"(fs));
    uint64_t off1 = fs - (uint64_t)tbss_var;
    uint64_t off2 = fs - (uint64_t)tdata_var;

    uint64_t start_offset = oe_sgx_get_thread_local_start_offset();
    printf(
        "tbss_var offset = %ld, tdata_var offset = %ld, computed start offset "
        "= %ld\n",
        off1,
        off2,
        start_offset);

    // Assert that tbss variables follow tdata variables.
    OE_TEST(start_offset >= off1);

    // Assert that compiler generated offset and the computed offsets are the
    // same.
    OE_TEST(start_offset == off2);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
