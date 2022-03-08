// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/tests.h>
#include "wrfsbase_t.h"

void enc_wrfsbase(int negative_test)
{
    static uint64_t temp_td[256];
    void* old_fs;
    void* new_fs;
    void* recovered_fs;

    temp_td[0] = (uint64_t)temp_td;

    asm volatile("mov %%fs:0, %0" : "=r"(old_fs));

    /* change FS */
    asm volatile("wrfsbase %0 " : : "a"(temp_td));
    asm volatile("mov %%fs:0, %0" : "=r"(new_fs));

    if (negative_test)
    {
        oe_sgx_td_t* td = oe_sgx_get_td();
        /* unreachable, dummy test to use td */
        OE_TEST(td->state == OE_TD_STATE_ABORTED);
    }

    /* restore FS */
    asm volatile("wrfsbase %0 " : : "a"(old_fs));
    asm volatile("mov %%fs:0, %0" : "=r"(recovered_fs));

    OE_TEST(new_fs == temp_td);
    OE_TEST(recovered_fs == old_fs);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
