#include <enc/host.h>
#include <enc/build.h>
#include <enc/sha.h>

#if 1
# define USE_DRIVER
#endif

static OE_SGXDevice* OpenDevice()
{
#ifdef USE_DRIVER
    return __OE_OpenSGXDriver();
#else
    return __OE_OpenSGXMeasurer();
#endif
}

static const SGX_EnclaveSettings* GetEnclaveSettings()
{
#ifdef USE_DRIVER
    return NULL;
#else
    static SGX_EnclaveSettings settings;

    memset(&settings, 0, sizeof(SGX_EnclaveSettings));
    settings.debug = 1;
    settings.numHeapPages = 2;
    settings.numStackPages = 1;
    settings.numTCS = 2;

    return &settings;
#endif
}

extern "C" void __ecall(OE_SGXEnclave* enclave);

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_SGXDevice* dev = NULL;
    OE_SGXEnclave enclave;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    if (!(dev = OpenDevice()))
        OE_PutErr("__OE_OpenSGXDriver() failed");

    if ((result = __OE_BuildEnclave(
        dev,
        argv[1],
        GetEnclaveSettings(),
        &enclave)) != OE_OK)
    {
        OE_PutErr("__OE_AddSegmentPages(): result=%u", result);
    }

#if 1
    __OE_DumpSGXEnclave(&enclave);
#endif

    __ecall(&enclave);

    return 0;
}
