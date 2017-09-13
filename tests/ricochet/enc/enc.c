#include <openenclave/enclave.h>
#include "../args.h"

OE_ECALL void Ricochet(void* args_)
{
    RicochetArgs* args = (RicochetArgs*)args_;

    OE_HostPrintf("Enclave Ricochet()\n");

    if (OE_CallHost("Ricochet", args) != OE_OK)
    {
        OE_Assert(0);
        return;
    }
}
