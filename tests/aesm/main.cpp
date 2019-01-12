// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(OE_USE_LIBSGX)
#include <sgx_dcap_ql_wrapper.h>
#else
#include <openenclave/internal/aesm.h>
#endif

#define SKIP_RETURN_CODE 2

int main()
{
    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(aesm)\n");
        return SKIP_RETURN_CODE;
    }

#if defined(OE_USE_LIBSGX)
    quote3_error_t err;
    sgx_target_info_t target_info = {};
    if (SGX_QL_SUCCESS != (err = sgx_qe_get_target_info(&target_info)))
    {
        printf("FAILED: Call returned %x\n", err);
        return -1;
    }
#else
    aesm_t* aesm;
    if (!(aesm = aesm_connect()))
    {
        fprintf(stderr, "aesm: failed to connect\n");
        exit(1);
    }
    aesm_disconnect(aesm);
#endif

    printf("=== passed all tests (aesm)\n");
    return 0;
}
