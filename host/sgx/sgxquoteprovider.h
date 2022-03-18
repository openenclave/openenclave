// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGX_HOST_QUOTE_PROVIDER_H
#define _OE_SGX_HOST_QUOTE_PROVIDER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/report.h>
#include "../../common/sgx/collateral.h"
#include "platformquoteprovider.h"

OE_EXTERNC_BEGIN

oe_result_t oe_initialize_quote_provider(void);
void oe_load_quote_provider(void);
void oe_quote_provider_log(sgx_ql_log_level_t level, const char* message);

typedef struct _oe_sgx_quote_provider
{
    void* handle;
    sgx_get_quote_verification_collateral_t
        get_sgx_quote_verification_collateral;
    sgx_free_quote_verification_collateral_t
        free_sgx_quote_verification_collateral;
    sgx_get_quote_verification_collateral_with_parameters_t
        get_sgx_quote_verification_collateral_with_parameters;
} oe_sgx_quote_provider_t;

// Set customized logging function for SGX provider.
// This is for OE SDK internal tools only and could be removed in future.
oe_result_t oe_sgx_set_quote_provider_logger(sgx_ql_logging_function_t logger);

// This is being deprecated and replaced by SGX_QL_SET_LOGGING_CALLBACK_NAME
#define SGX_QL_SET_LOGGING_FUNCTION_NAME "sgx_ql_set_logging_function"
#define SGX_QL_SET_LOGGING_CALLBACK_NAME "sgx_ql_set_logging_callback"
#define SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_NAME \
    "sgx_ql_get_quote_verification_collateral"
#define SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_WITH_PARAMETERS_NAME \
    "sgx_ql_get_quote_verification_collateral_with_params"
#define SGX_QL_FREE_QUOTE_VERIFICATION_COLLATERAL_NAME \
    "sgx_ql_free_quote_verification_collateral"

/**
 * Version of the supported SGX quote verification collateral, which will
 * reflect the version of the PCCS/PCS API used to retrieve the collateral.
 * For PCS V1 and V2 APIs, the ‘version’ field will have a value of 0x1.
 * That is, major_version = 1 and minor_version = 0.
 * For PCS V3 APIs, major_version = 3 and the minor_version can be 0 or 1.
 * minor_verion of 0 (version = 0x00000003) indicates the CRL’s are formatted
 * in Base16 encoded DER. A minor version of 1 (version = 0x00010003) indicates
 * the CRL’s are formatted in raw binary DER.
 */
#define SGX_QL_QVE_COLLATERAL_VERSION_1 (0x00000001)
#define SGX_QL_QVE_COLLATERAL_VERSION_3_0 (0x00000003)
#define SGX_QL_QVE_COLLATERAL_VERSION_3_1 (0x00010003)

OE_EXTERNC_END

#endif // _OE_SGX_HOST_QUOTE_PROVIDER_H