// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/eeid.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/str.h>
#include <stdio.h>
#include <sys/stat.h>
#include "../host/sgx/enclave.h"
#include "oe_err.h"
#include "oeinfo.h"

#ifdef OE_WITH_EXPERIMENTAL_EEID
int oedump_eeid(const char* enclave)
{
    int ret = 1;
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t enc;
    oe_sgx_enclave_properties_t props;
    oe_sgx_load_context_t context;

    /* Load the enclave properties from the enclave.
     * Note that oesign expects that the enclave must already have the .oeinfo
     * section allocated, and cannot currently inject it into the ELF.
     * The load stack (oe_load_enclave_image) requires that the oeinfo_rva be
     * found or fails the load.
     */
    OE_CHECK_ERR(
        oe_read_oeinfo_sgx(enclave, &props),
        "Failed to load enclave: %s: result=%s (%#x)",
        enclave,
        oe_result_str(result),
        result);

    /* Check whether enclave properties are valid */
    {
        const char* field_name;
        OE_CHECK_ERR(
            oe_sgx_validate_enclave_properties(&props, &field_name),
            "Invalid enclave property value: %s",
            field_name);
    }

    /* Initialize the context parameters for measurement only */
    OE_CHECK_ERR(
        oe_sgx_initialize_load_context(
            &context, OE_SGX_LOAD_TYPE_MEASURE, props.config.attributes),
        "oe_sgx_initialize_load_context() failed");

    /* Build an enclave with EEID enabled */
    oe_enclave_setting_eeid_t eeid_setting = {{0}};
    context.eeid_setting = &eeid_setting;

    OE_CHECK_ERR(
        oe_sgx_build_enclave(&context, enclave, &props, &enc),
        "oe_sgx_build_enclave(): result=%s (%#x)",
        oe_result_str(result),
        result);

    printf("=== Extended Information for EEID: \n");
    printf("H=");
    oe_hex_dump(context.eeid->hash_state.H, sizeof(uint32_t) * 8);
    printf("N=");
    oe_hex_dump(context.eeid->hash_state.N, sizeof(uint32_t) * 2);
    printf("base_sigstruct=");
    oe_hex_dump(context.eeid->signature, context.eeid->signature_size);
    printf("vaddr=%lu", context.eeid->vaddr);
    printf("\n");

    ret = 0;

done:

    free(context.eeid);
    oe_sgx_cleanup_load_context(&context);

    return ret;
}
#endif