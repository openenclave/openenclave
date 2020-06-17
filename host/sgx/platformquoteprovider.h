// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once
#ifndef PLATFORM_QUOTE_PROVIDER_H
#define PLATFORM_QUOTE_PROVIDER_H

#include <stdint.h>

/*****************************************************************************
 * Data types and interfaces for getting platform revocation info. This
 * includes fetching CRLs as well as the Intel-defined TCB info.
 ****************************************************************************/
typedef enum _sgx_plat_error_t
{
    SGX_PLAT_ERROR_OK,
    SGX_PLAT_ERROR_OUT_OF_MEMORY,
    SGX_PLAT_ERROR_INVALID_PARAMETER,
    SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE,
    SGX_PLAT_NO_DATA_FOUND,
    SGX_PLAT_ERROR_OVERFLOW
} sgx_plat_error_t;

/*****************************************************************************
 * Data types and interfaces for getting all quote verification collateral.
 ****************************************************************************/

#ifndef __sgx_ql_qve_collateral_t // The __sgx_ql_qve_collateral_t can also be
                                  // defined in QvE _t/_u.h
#define __sgx_ql_qve_collateral_t
typedef struct _sgx_ql_qve_collateral_t
{
    uint32_t version; /// version = 1.  PCK Cert chain is in the Quote.
    char* pck_crl_issuer_chain;
    uint32_t pck_crl_issuer_chain_size;
    char* root_ca_crl; /// Root CA CRL
    uint32_t root_ca_crl_size;
    char* pck_crl; /// PCK Cert CRL
    uint32_t pck_crl_size;
    char* tcb_info_issuer_chain;
    uint32_t tcb_info_issuer_chain_size;
    char* tcb_info; /// TCB Info structure
    uint32_t tcb_info_size;
    char* qe_identity_issuer_chain;
    uint32_t qe_identity_issuer_chain_size;
    char* qe_identity; /// QE Identity Structure
    uint32_t qe_identity_size;
} sgx_ql_qve_collateral_t;
#endif //__sgx_ql_qve_collateral_t

typedef sgx_plat_error_t (*sgx_get_quote_verification_collateral_t)(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    sgx_ql_qve_collateral_t** pp_qve_collateral);

typedef void (*sgx_free_quote_verification_collateral_t)(
    sgx_ql_qve_collateral_t* p_qve_collateral);

/*****************************************************************************
 * Data types and interfaces for configuration the platform quote provider
 * library.
 ****************************************************************************/
typedef enum _sgx_ql_log_level_t
{
    SGX_QL_LOG_ERROR,
    SGX_QL_LOG_INFO
} sgx_ql_log_level_t;

/// Function signature used for logging from within the library
typedef void (
    *sgx_ql_logging_function_t)(sgx_ql_log_level_t level, const char* message);

/// Set the callback used for recording log information.
typedef sgx_plat_error_t (*sgx_ql_set_logging_function_t)(
    sgx_ql_logging_function_t logger);

/// Set the base URL for the certificate host service. This is typically done
/// for testing.
typedef sgx_plat_error_t (*sgx_ql_set_base_url_t)(const char* url);

#endif // #ifndef PLATFORM_QUOTE_PROVIDER_H
