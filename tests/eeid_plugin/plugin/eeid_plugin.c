
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/attestation/sgx/attester.h>
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/attestation/sgx/verifier.h>

#include "eeid_plugin.h"

oe_result_t eeid_on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    oe_result_t result = OE_UNEXPECTED;

#ifdef OE_BUILD_ENCLAVE
    oe_attester_t* sgx_attest = oe_sgx_plugin_attester();
    result = oe_register_attester(sgx_attest, NULL, 0);
    if (result != OE_ALREADY_EXISTS)
        return result;
#endif

    oe_verifier_t* sgx_verify = oe_sgx_plugin_verifier();
    result = oe_register_verifier(sgx_verify, NULL, 0);
    return result == OE_ALREADY_EXISTS ? OE_OK : result;
}

oe_result_t eeid_on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    oe_result_t result = OE_UNEXPECTED;

#ifdef OE_BUILD_ENCLAVE
    oe_attester_t* sgx_attest = oe_sgx_plugin_attester();
    result = oe_unregister_attester(sgx_attest);
    if (result != OE_OK && result != OE_NOT_FOUND)
        return result;
#endif

    oe_verifier_t* sgx_verify = oe_sgx_plugin_verifier();
    result = oe_unregister_verifier(sgx_verify);
    if (result != OE_OK && result != OE_NOT_FOUND)
        return result;

    return OE_OK;
}