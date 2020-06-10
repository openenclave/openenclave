// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/tests.h>
#include "ecall_t.h"

int TestSetjmp()
{
    oe_jmpbuf_t buf;

    int rc = oe_setjmp(&buf);

    if (rc == 999)
        return rc;

    oe_longjmp(&buf, 999);
    return 0;
}

void enc_test(test_args* args)
{
    /* Set output arguments */
    memset(args, 0xDD, sizeof(test_args));
    args->magic = NEW_MAGIC;
    args->self = args;
    args->mm = 12;
    args->dd = 31;
    args->yyyy = 1962;
    args->magic2 = NEW_MAGIC;

    /* Get thread data */
    const oe_sgx_td_t* td;
    if ((td = oe_sgx_get_td()))
    {
        args->thread_data = *td;
        args->thread_data_addr = reinterpret_cast<uint64_t>(td);
    }

    /* Get enclave offsets and bases */
    args->base = const_cast<void*>(__oe_get_enclave_base());
    args->base_heap_page = oe_get_base_heap_page();
    args->num_heap_pages = oe_get_num_heap_pages();
    args->num_pages = oe_get_num_pages();

    /* Test the oe_setjmp/oe_longjmp functions */
    args->setjmp_result = TestSetjmp();

    /* Test snprintf() */
    {
        {
            char buf[128];
            int n = oe_snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(oe_strcmp(buf, "2147483647") == 0);
            OE_TEST(n == 10);
        }

        {
            char buf[6];
            int n = oe_snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(oe_strcmp(buf, "21474") == 0);
            OE_TEST(n == 10);
        }

        {
            char buf[2];
            int n = oe_snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(oe_strcmp(buf, "2") == 0);
            OE_TEST(n == 10);
        }

        {
            char buf[1];
            int n = oe_snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(oe_strcmp(buf, "") == 0);
            OE_TEST(n == 10);
        }

        {
            int n = oe_snprintf(NULL, 0, "%d", 2147483647);
            OE_TEST(n == 10);
        }

        {
            char buf[128];
            int n = oe_snprintf(buf, sizeof(buf), "UINT_MAX=%u", 4294967295U);
            OE_TEST(oe_strcmp(buf, "UINT_MAX=4294967295") == 0);
            OE_TEST(n == 19);
        }

        {
            char buf[128];
            int n = oe_snprintf(buf, sizeof(buf), "INT_MAX=%u", 2147483647);
            OE_TEST(oe_strcmp(buf, "INT_MAX=2147483647") == 0);
            OE_TEST(n == 18);
        }

        {
            char buf[128];
            int n =
                oe_snprintf(buf, sizeof(buf), "INT_MIN=%d", -2147483647 - 1);
            OE_TEST(oe_strcmp(buf, "INT_MIN=-2147483648") == 0);
            OE_TEST(n == 19);
        }

        {
            char buf[128];
            int n = oe_snprintf(
                buf,
                sizeof(buf),
                "ULONG_MAX=%llu",
                OE_LLU(18446744073709551615UL));
            OE_TEST(oe_strcmp(buf, "ULONG_MAX=18446744073709551615") == 0);
            OE_TEST(n == 30);
        }

        {
            char buf[128];
            int n = oe_snprintf(
                buf, sizeof(buf), "LONG_MAX=%lld", OE_LLD(9223372036854775807));
            OE_TEST(oe_strcmp(buf, "LONG_MAX=9223372036854775807") == 0);
            OE_TEST(n == 28);
        }

        {
            char buf[128];
            int n = oe_snprintf(
                buf,
                sizeof(buf),
                "LONG_MIN=%lld",
                OE_LLD(-9223372036854775807 - 1));
            OE_TEST(oe_strcmp(buf, "LONG_MIN=-9223372036854775808") == 0);
            OE_TEST(n == 29);
        }
        {
            char buf[12];
            int n = oe_snprintf(
                buf,
                sizeof(buf),
                "LONG_MIN=%lld",
                OE_LLD(-9223372036854775807 - 1));
            OE_TEST(oe_strcmp(buf, "LONG_MIN=-9") == 0);
            OE_TEST(n == 29);
        }
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
