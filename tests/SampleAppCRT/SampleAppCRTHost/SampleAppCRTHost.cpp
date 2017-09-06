#include <limits.h>
#include <openenclave/host.h>

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = OE_CreateEnclave(argv[1], 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %s\n", argv[0], argv[1]);
        return 1;
    }

    int returnValue = INT_MIN;
    if ((result = OE_CallEnclave(enclave, "Test", &returnValue)) != OE_OK)
    {
        fprintf(stderr, "%s: ecall failed: result=%u\n", argv[0], result);
        return 1;
    }

    if (returnValue != 0)
    {
        fprintf(stderr, "ecall failed: returnValue=%d\n", returnValue);
        return 1;
    }

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (SampleAppCRTHost)\n");

    return 0;
}
