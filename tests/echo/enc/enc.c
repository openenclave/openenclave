#include <openenclave/enclave.h>
#include "../args.h"

OE_EXPORT void OE_Constructor(void)
{
    OE_HostPrintf("Hello from Echo constructor!\n");
}

OE_EXPORT void OE_Destructor(void)
{
    OE_HostPrintf("Hello from Echo destructor!\n");
}

OE_ECALL void Echo(void* args_)
{
    EchoArgs* args = (EchoArgs*)args_;

    if (!OE_IsOutsideEnclave(args, sizeof(EchoArgs)))
    {
        args->ret = -1;
        return;
    }

    if (OE_Strcmp(args->in, "Hello World") != 0)
    {
        args->ret = -1;
        return;
    }

    args->str1 = OE_HostStackStrdup("OE_HostStackStrdup1");
    args->str2 = OE_HostStackStrdup("OE_HostStackStrdup2");
    args->str3 = OE_HostStackStrdup("OE_HostStackStrdup3");

    if (OE_CallHost("Echo", args) != OE_OK)
    {
        args->ret = -1;
        return;
    }

    OE_HostPrintf("Hello from Echo function!\n");

    args->ret = 0;
}
