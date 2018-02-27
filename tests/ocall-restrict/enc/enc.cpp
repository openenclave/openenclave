#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include "../args.h"

static int counter;

/*
   Call host via OCalls with different ECall-restrictions. The host
   will attempt to re-enter via ECalls. Check results.

   The argPtr is shared w/ the host on purpose, both for communicating the
   function-call arguments (in the format OE_OCallFunction() provides them),
   as well as for return values.

 */
OE_ECALL void Test(void* argPtr)
{
    OE_Result res;
    TestORArgs* ta = (TestORArgs*)argPtr;
    OE_CallHostArgs* cha = &ta->callHost;

    printf("%s(): Called, ta=%p\n", __FUNCTION__, ta);

    /* Perform regular ocall w/ ecall. We mimic OE_OCallFunction() and use
     * internal knowledge of it to pass OE_OCALL_FLAG_NOT_REENTRANT later. */
    cha->args = argPtr;
    strcpy(cha->func, "TestEcall");

    printf("%s(): OCALL...\n", __FUNCTION__);
    res = OE_OCall(OE_FUNC_CALL_HOST, (uint64_t)cha, NULL, 0);
    printf(
        "%s(): OCALL returned. res=%x, ta->result=%x, counter=%x\n",
        __FUNCTION__,
        res,
        ta->result,
        counter);
    OE_Assert(res == OE_OK);
    OE_Assert(ta->result == OE_OK);
    OE_Assert(counter == 1);

    /* Perform restricted ocall, expect ecall to fail */
    printf("%s(): OCALL(restricted)...\n", __FUNCTION__);
    res = OE_OCall(
        OE_FUNC_CALL_HOST, (uint64_t)cha, NULL, OE_OCALL_FLAG_NOT_REENTRANT);
    printf(
        "%s(): OCALL returned. res=%x, ta->result=%x, counter=%x\n",
        __FUNCTION__,
        res,
        ta->result,
        counter);
    OE_Assert(res == OE_OK);
    OE_Assert(ta->result == OE_UNEXPECTED);
    OE_Assert(counter == 1);

    /* Perform regular ocall w/ ecall */
    res = OE_OCall(OE_FUNC_CALL_HOST, (uint64_t)cha, NULL, 0);
    OE_Assert(res == OE_OK);
    OE_Assert(ta->result == OE_OK);
    OE_Assert(counter == 2);

    ta->result = OE_OK;

    printf("%s(): Returning\n", __FUNCTION__);
}

OE_ECALL void ECallNested(void* args)
{
    OE_UNUSED(args);
    printf("%s(): Called, counter=%d\n", __FUNCTION__, counter);
    counter++;
    printf("%s(): Returning, counter=%d\n", __FUNCTION__, counter);
}
