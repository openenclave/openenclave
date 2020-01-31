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
 * Data types and interfaces for getting platform revocation info. This
 * includes fetching CRLs as well as the Intel-defined TCB info.
 ****************************************************************************/
typedef enum _sgx_ql_revocation_info_version_t
{
    SGX_QL_REVOCATION_INFO_VERSION_1 = 1
} sgx_ql_revocation_info_version_t;

typedef struct _sgx_ql_get_revocation_info_params_t
{
    sgx_ql_revocation_info_version_t version;
    uint32_t fmspc_size;  // size of fmspc
    const uint8_t* fmspc; // Family-Model-Stepping-Platform-Custom

    uint32_t crl_url_count; // number of CRL distribution point URL
    const char* const*
        crl_urls; // array of CRL distribution URLs, null-terminated
} sgx_ql_get_revocation_info_params_t;

typedef struct _sgx_ql_crl_data_t
{
    uint32_t crl_data_size; // size of crl_data
    char* crl_data;         // DER-encoded.

    uint32_t crl_issuer_chain_size; // size of issuer chain for the CRL
    char* crl_issuer_chain;         // PEM-encoded certificate chain
} sgx_ql_crl_data_t;

typedef struct _sgx_ql_revocation_info_t
{
    sgx_ql_revocation_info_version_t version;

    uint32_t tcb_info_size;         // size of tcb_info
    char* tcb_info;                 // Intel-signed TCB info structure (JSON)
    uint32_t tcb_issuer_chain_size; // size of issuer chain for TCB info
    char* tcb_issuer_chain;         // PEM-encoded certificate chain

    uint32_t crl_count;      // number of CRL data blobs returned
    sgx_ql_crl_data_t* crls; // array of CRL data blobs
} sgx_ql_revocation_info_t;

typedef sgx_plat_error_t (*sgx_ql_get_revocation_info_t)(
    const sgx_ql_get_revocation_info_params_t* params,
    sgx_ql_revocation_info_t** pp_revocation_info);

typedef void (*sgx_ql_free_revocation_info_t)(
    sgx_ql_revocation_info_t* p_revocation_info);

/*****************************************************************************
 * Data types and interfaces for getting qe identity info
 ****************************************************************************/

typedef struct _sgx_qe_identity_info_t
{
    uint32_t qe_id_info_size;   // size of qe identity
    char* qe_id_info;           // qe identity info structure (JSON)
    uint32_t issuer_chain_size; // size of issuer chain for qe identity info
    char* issuer_chain;         // PEM-encoded certificate chain
} sgx_qe_identity_info_t;

typedef sgx_plat_error_t (*sgx_get_qe_identity_info_t)(
    sgx_qe_identity_info_t** pp_qe_identity_info);

typedef void (*sgx_free_qe_identity_info_t)(
    sgx_qe_identity_info_t* p_qe_identity_info);

/*****************************************************************************
 * Data types and interfaces for getting all quote verification collateral.
 ****************************************************************************/

typedef sgx_plat_error_t (*sgx_get_quote_verification_collateral_t)(
    sgx_qe_identity_info_t** pp_qe_identity_info);

typedef void (*sgx_free_quote_verification_collateral_t)(
    sgx_qe_identity_info_t* p_qe_identity_info);

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
