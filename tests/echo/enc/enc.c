#include <openenclave.h>
#include "../args.h"

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

    if (OE_CallHost("Echo", args) != OE_OK)
    {
        args->ret = -1;
        return;
    }

    OE_HostPuts("Hello from Echo enclave!");

    args->ret = 0;
}
