// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/jump.h>
#include <openenclave/bits/tests.h>
#include <openenclave/enclave.h>
#include "../args.h"

void MyECall(uint64_t argIn, uint64_t* argOut)
{
    if (argOut)
        *argOut = argIn * 3;
}

/* Register custom ECall on load */
static OE_Result s_registerResult = OE_RegisterECall(0, MyECall);

int TestSetjmp()
{
    OE_Jmpbuf buf;

    int rc = OE_Setjmp(&buf);

    if (rc == 999)
        return rc;

    OE_Longjmp(&buf, 999);
    return 0;
}

OE_ECALL void Test(void* args_)
{
    TestArgs* args = (TestArgs*)args_;

    if (!args_)
        return;

    /* Verify that registration of ECall at initialization succeeded */
    OE_TEST(s_registerResult == OE_OK);

    /* Set output arguments */
    OE_Memset(args, 0xDD, sizeof(TestArgs));
    args->magic = NEW_MAGIC;
    args->self = args;
    args->mm = 12;
    args->dd = 31;
    args->yyyy = 1962;
    args->magic2 = NEW_MAGIC;

    /* Get thread data */
    const OE_ThreadData* td;
    if ((td = OE_GetThreadData()))
    {
        args->threadData = *td;
        args->threadDataAddr = (uint64_t)td;
    }

    /* Get enclave offsets and bases */
    args->baseHeapPage = __oe_baseHeapPage;
    args->numHeapPages = __oe_numHeapPages;
    args->numPages = __oe_numPages;
    args->base = __OE_GetEnclaveBase();

    /* Test the OE_Setjmp/OE_Longjmp functions */
    args->setjmpResult = TestSetjmp();

    /* Test snprintf() */
    {
        {
            char buf[128];
            int n = OE_Snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(OE_Strcmp(buf, "2147483647") == 0);
            OE_TEST(n == 10);
        }

        {
            char buf[6];
            int n = OE_Snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(OE_Strcmp(buf, "21474") == 0);
            OE_TEST(n == 10);
        }

        {
            char buf[2];
            int n = OE_Snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(OE_Strcmp(buf, "2") == 0);
            OE_TEST(n == 10);
        }

        {
            char buf[1];
            int n = OE_Snprintf(buf, sizeof(buf), "%d", 2147483647);
            OE_TEST(OE_Strcmp(buf, "") == 0);
            OE_TEST(n == 10);
        }

        {
            int n = OE_Snprintf(NULL, 0, "%d", 2147483647);
            OE_TEST(n == 10);
        }

        {
            char buf[128];
            int n = OE_Snprintf(buf, sizeof(buf), "UINT_MAX=%u", 4294967295U);
            OE_TEST(OE_Strcmp(buf, "UINT_MAX=4294967295") == 0);
            OE_TEST(n == 19);
        }

        {
            char buf[128];
            int n = OE_Snprintf(buf, sizeof(buf), "INT_MAX=%u", 2147483647);
            OE_TEST(OE_Strcmp(buf, "INT_MAX=2147483647") == 0);
            OE_TEST(n == 18);
        }

        {
            char buf[128];
            int n =
                OE_Snprintf(buf, sizeof(buf), "INT_MIN=%d", -2147483647 - 1);
            OE_TEST(OE_Strcmp(buf, "INT_MIN=-2147483648") == 0);
            OE_TEST(n == 19);
        }

        {
            char buf[128];
            int n = OE_Snprintf(
                buf, sizeof(buf), "ULONG_MAX=%llu", 
                    OE_LLU(18446744073709551615UL));
            OE_TEST(OE_Strcmp(buf, "ULONG_MAX=18446744073709551615") == 0);
            OE_TEST(n == 30);
        }

        {
            char buf[128];
            int n = OE_Snprintf(
                buf, sizeof(buf), "LONG_MAX=%lld", OE_LLD(9223372036854775807));
            OE_TEST(OE_Strcmp(buf, "LONG_MAX=9223372036854775807") == 0);
            OE_TEST(n == 28);
        }

        {
            char buf[128];
            int n = OE_Snprintf(
                buf, sizeof(buf), "LONG_MIN=%lld", OE_LLD(-9223372036854775807 - 1));
            OE_TEST(OE_Strcmp(buf, "LONG_MIN=-9223372036854775808") == 0);
            OE_TEST(n == 29);
        }
        {
            char buf[12];
            int n = OE_Snprintf(
                buf, sizeof(buf), "LONG_MIN=%lld", OE_LLD(-9223372036854775807 - 1));
            OE_TEST(OE_Strcmp(buf, "LONG_MIN=-9") == 0);
            OE_TEST(n == 29);
        }
    }
}
