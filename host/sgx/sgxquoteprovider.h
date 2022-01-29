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
} oe_sgx_quote_provider_t;

bool oe_set_quote_provider_logger(
    oe_sgx_quote_provider_t* provider,
    sgx_ql_logging_function_t logger);

// This is being deprecated and replaced by SGX_QL_SET_LOGGING_CALLBACK_NAME
#define SGX_QL_SET_LOGGING_FUNCTION_NAME "sgx_ql_set_logging_function"
#define SGX_QL_SET_LOGGING_CALLBACK_NAME "sgx_ql_set_logging_callback"
#define SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_NAME \
    "sgx_ql_get_quote_verification_collateral"
#define SGX_QL_FREE_QUOTE_VERIFICATION_COLLATERAL_NAME \
    "sgx_ql_free_quote_verification_collateral"

/**
 * Version of the supported SGX quote verification collateral, which will
 * reflect the version of the PCCS/PCS API used to retrieve the collateral.
 * For V1 and V2 APIs, the ‘version’ field with have a value of 1.
 * For V3 APIs, the ‘version’ field will have the value of 3."
 */
#define SGX_QL_QVE_COLLATERAL_VERSION_1 (1)
#define SGX_QL_QVE_COLLATERAL_VERSION_3 (3)

OE_EXTERNC_END

#endif // _OE_SGX_HOST_QUOTE_PROVIDER_H