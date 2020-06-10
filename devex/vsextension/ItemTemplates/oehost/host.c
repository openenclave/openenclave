#include <openenclave/host.h>
#include "$enclavename$_u.h"

oe_result_t create_$enclavename$_enclave(
    const char* enclave_name,
    oe_enclave_t** out_enclave)
{
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = 0;
    oe_result_t result;

    *out_enclave = NULL;

    // Create the enclave
#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
    result = oe_create_$enclavename$_enclave(
        enclave_name, OE_ENCLAVE_TYPE_AUTO, enclave_flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        printf(
            "Error %d creating enclave, trying simulation mode...\n", result);
        enclave_flags |= OE_ENCLAVE_FLAG_SIMULATE;
        result = oe_create_$enclavename$_enclave(
            enclave_name,
            OE_ENCLAVE_TYPE_AUTO,
            enclave_flags,
            NULL,
            0,
            &enclave);
    }
    if (result != OE_OK)
    {
        return result;
    }

    *out_enclave = enclave;
    return OE_OK;
}

void sample_enclave_call(void)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = create_$enclavename$_enclave(
#ifdef OE_USE_OPTEE
        "$enclaveguid$",
#else
        "$enclavename$.elf.signed",
#endif
        &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    /* Make calls into the enclave... */
    int retval;
    result = ecall_DoWorkInEnclave(enclave, &retval);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into ecall_DoWorkInEnclave failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

exit:
    /* Clean up the enclave if we created one. */
    if (enclave != NULL)
    {
        oe_terminate_enclave(enclave);
    }
}

/* Add implementations of any OCALLs here. */
void ocall_DoWorkInHost(void)
{
    printf("Hello from within ocall_DoWorkInHost\n");
}
