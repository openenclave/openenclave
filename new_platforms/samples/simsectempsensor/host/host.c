// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>

#include "simsectempsensor_u.h"

#ifdef OE_USE_SGX
#define TA_BIN "simsectempsensor_enclave"
#else
#define TA_BIN "97d140f4-5f59-4d1f-9735-cb21d49e7eb8"
#endif

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = 0;

    // Create the enclave
#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
    result = oe_create_simsectempsensor_enclave(
        TA_BIN, OE_ENCLAVE_TYPE_UNDEFINED, enclave_flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    // TODO initialize IoTHub client

    while (TRUE)
    {
        // Call into the enclave
        int hostResult;
        uint32_t sensor_value;
        uint8_t signature_buffer[128];
        size_t signature_size = 0;
        result = enclave_readsensor(
            enclave,
            &hostResult,
            &sensor_value,
            signature_buffer,
            sizeof(signature_buffer),
            &signature_size);
        if (result != OE_OK)
        {
            fprintf(
                stderr,
                "calling into enclave_helloworld failed: result=%u (%s)\n",
                result,
                oe_result_str(result));
            goto next;
        }
        if (hostResult != OE_OK)
        {
            fprintf(stderr, "OCALL failed: result=%u\n", hostResult);
            goto next;
        }

        // TODO upload to IoTHub
        printf(
            "Read value: %d\n",
            sensor_value);

next:
        Sleep(1000);
    }

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
