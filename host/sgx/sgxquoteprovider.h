// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGX_HOST_QUOTE_PROVIDER_H
#define _OE_SGX_HOST_QUOTE_PROVIDER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/report.h>
#include "../../common/sgx/qeidentity.h"
#include "../../common/sgx/revocation.h"
#include "platformquoteprovider.h"

OE_EXTERNC_BEGIN

oe_result_t oe_initialize_quote_provider(void);
void oe_load_quote_provider(void);
void oe_quote_provider_log(sgx_ql_log_level_t level, const char* message);

typedef struct _oe_sgx_quote_provider
{
    void* handle;
    sgx_ql_get_revocation_info_t get_revocation_info;
    sgx_ql_free_revocation_info_t free_revocation_info;
    sgx_get_qe_identity_info_t get_qe_identity_info;
    sgx_free_qe_identity_info_t free_qe_identity_info;
} oe_sgx_quote_provider_t;

#define SGX_QL_GET_REVOCATION_INFO_NAME "sgx_ql_get_revocation_info"
#define SGX_QL_FREE_REVOCATION_INFO_NAME "sgx_ql_free_revocation_info"
#define SGX_QL_GET_QE_IDENTITY_INFO_NAME "sgx_get_qe_identity_info"
#define SGX_QL_FREE_QE_IDENTITY_INFO_NAME "sgx_free_qe_identity_info"
#define SGX_QL_SET_LOGGING_FUNCTION_NAME "sgx_ql_set_logging_function"

OE_EXTERNC_END

#endif // _OE_SGX_HOST_QUOTE_PROVIDER_H
