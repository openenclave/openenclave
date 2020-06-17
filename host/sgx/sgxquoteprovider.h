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

#define SGX_QL_SET_LOGGING_FUNCTION_NAME "sgx_ql_set_logging_function"
#define SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_NAME \
    "sgx_ql_get_quote_verification_collateral"
#define SGX_QL_FREE_QUOTE_VERIFICATION_COLLATERAL_NAME \
    "sgx_ql_free_quote_verification_collateral"

/*! Version of the supported SGX quote verification collateral  */
#define SGX_QL_QVE_COLLATERAL_VERSION (1)

OE_EXTERNC_END

#endif // _OE_SGX_HOST_QUOTE_PROVIDER_H