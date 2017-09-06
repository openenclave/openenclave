#include <openenclave/enclave.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/jump.h>
#include "../args.h"

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
        args->threadDataAddr = (unsigned long long)td;
    }

    /* Get enclave offsets and bases */
    args->baseHeapPage = __oe_baseHeapPage;
    args->numHeapPages = __oe_numHeapPages;
    args->numPages = __oe_numPages;
    args->base = __OE_GetEnclaveBase();

    /* Test the OE_Setjmp/OE_Longjmp functions */
    args->setjmpResult = TestSetjmp();
}
