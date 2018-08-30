#include <openenclave/host.h>

int main(int argc, const char* argv[])
{
    oe_result_t result;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    oe_enclave_t* enclave;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }


    /* Create the enclave */
    result = oe_create_enclave(argv[1], type, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: failed to create enclave: %s\n", argv[0], argv[1]);
        exit(1);
    }

    /* Invoke test_sample() ECALL */
    result = oe_call_enclave(enclave, "test_sample", NULL);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: failed to invoke ECALL\n", argv[0]);
        exit(1);
    }

    result = oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
