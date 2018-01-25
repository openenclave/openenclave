#include <openenclave/enclave.h>

OE_ECALL void EnclaveEcho(void* args)
{
    OE_CallHost("HostEcho", args);
}
