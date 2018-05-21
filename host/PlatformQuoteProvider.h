//----------------------------------------------------------------------------
// <copyright file="PlatformQuoteProvider.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//----------------------------------------------------------------------------
#pragma once

// ReSharper disable CppInconsistentNaming
// Intel defined the coding style - ReSharper will complain. Suppress it, since
// we want the
// public-facing interfaces to match up with the Intel code.

//////////////////////////////////////////////////////////////////////////////
// TODO: Once we integrate this into the OE stack, we should have access to
//       the real Intel headers. When that happens, the *sgx* typedefs should
//       all be removed from this file. Backlog Item 2263219
#include <stdint.h>

typedef uint16_t sgx_isv_svn_t;

typedef struct _sgx_cpu_svn_t
{
    uint8_t svn[16];
} sgx_cpu_svn_t;

typedef struct _sgx_key_id_t
{
    uint8_t id[32];
} sgx_key_id_t;

typedef struct _sgx_ql_config_t
{
    sgx_cpu_svn_t* p_cert_cpu_svn;
    sgx_isv_svn_t* p_cert_pce_isv_svn;
    uint32_t* p_cert_data_size;
    uint8_t* p_cert_data;
} sgx_ql_config_t;

typedef struct _sgx_ql_pck_cert_id_t
{
    uint8_t* p_qe3_id;
    uint32_t qe3_id_size;
    sgx_cpu_svn_t* p_platform_cpu_svn;
    sgx_isv_svn_t* p_platform_pce_isv_svn;
    uint8_t* p_encrypted_ppid;
    uint32_t encrypted_ppid_size;
    uint8_t crypto_suite;
    uint16_t pce_id;
} sgx_ql_pck_cert_id_t;

#define SGX_QL_MK_ERROR(x) (0x0000E000 | (x))

typedef enum _quote3_error_t {
    SGX_QL_SUCCESS = 0x0000, ///< Success
    SGX_QL_ERROR_MIN = SGX_QL_MK_ERROR(
        0x0001), ///< Indicate max error to allow better translation.
    SGX_QL_ERROR_UNEXPECTED = SGX_QL_MK_ERROR(0x0001), ///< Unexpected error
    SGX_QL_ERROR_INVALID_PARAMETER =
        SGX_QL_MK_ERROR(0x0002), ///< The parameter is incorrect
    SGX_QL_ERROR_OUT_OF_MEMORY = SGX_QL_MK_ERROR(
        0x0003), ///< Not enough memory is available to complete this operation
    SGX_QL_ERROR_ECDSA_ID_MISMATCH =
        SGX_QL_MK_ERROR(0x0004), ///< Expected ECDSA_ID does not match the value
                                 ///stored in the ECDSA Blob
    SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR =
        SGX_QL_MK_ERROR(0x0005), ///< The ECDSA blob pathname is too large
    SGX_QL_FILE_ACCESS_ERROR =
        SGX_QL_MK_ERROR(0x0006), ///< Error accessing ECDSA blob
    SGX_QL_ERROR_STORED_KEY =
        SGX_QL_MK_ERROR(0x0007), ///< Cached ECDSA key is invalid
    SGX_QL_ERROR_PUB_KEY_ID_MISMATCH = SGX_QL_MK_ERROR(
        0x0008), ///< Cached ECDSA key does not match requested key
    SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME =
        SGX_QL_MK_ERROR(0x0009), ///< PCE use the incorrect signature scheme
    SGX_QL_ATT_KEY_BLOB_ERROR = SGX_QL_MK_ERROR(
        0x000a), ///< There is a problem with the attestation key blob.
    SGX_QL_UNSUPPORTED_ATT_KEY_ID =
        SGX_QL_MK_ERROR(0x000b), ///< Unsupported attestation key ID.
    SGX_QL_UNSUPPORTED_LOADING_POLICY =
        SGX_QL_MK_ERROR(0x000c), ///< Unsupported enclave loading policy.
    SGX_QL_INTERFACE_UNAVAILABLE =
        SGX_QL_MK_ERROR(0x000d), ///< Unable to load the QE enclave
    SGX_QL_PLATFORM_LIB_UNAVAILABLE =
        SGX_QL_MK_ERROR(0x000e), ///< Unable to find the platform library with
                                 ///the dependent APIs.  Not fatal.
    SGX_QL_ATT_KEY_NOT_INITIALIZED =
        SGX_QL_MK_ERROR(0x000f), ///< The attestation key doesn't exist or has
                                 ///not been certified.
    SGX_QL_ATT_KEY_CERT_DATA_INVALID =
        SGX_QL_MK_ERROR(0x0010), ///< The certification data retrieved from the
                                 ///platform library is invalid.
    SGX_QL_NO_PLATFORM_CERT_DATA = SGX_QL_MK_ERROR(
        0x0011), ///< The platform library doesn't have any platfrom cert data.
    SGX_QL_OUT_OF_EPC = SGX_QL_MK_ERROR(
        0x0012), ///< Not enough memory in the EPC to load the enclave.
    SGX_QL_ERROR_REPORT = SGX_QL_MK_ERROR(
        0x0013), ///< There was a problem verifying an SGX REPORT.
    SGX_QL_ENCLAVE_LOST = SGX_QL_MK_ERROR(0x0014), ///< Interfacing to the
                                                   ///enclave failed due to a
                                                   ///power transition.
    SGX_QL_INVALID_REPORT = SGX_QL_MK_ERROR(
        0x0015), ///< Error verifying the application enclave's report.
    SGX_QL_ENCLAVE_LOAD_ERROR = SGX_QL_MK_ERROR(
        0x0016), ///< Unable to load the enclaves.  Could be due to file I/O
                 ///error, loading infrastructure error.
    SGX_QL_UNABLE_TO_GENERATE_QE_REPORT = SGX_QL_MK_ERROR(
        0x0017), ///< The QE was unable to generate its own report targeting the
                 ///application enclave either
    SGX_QL_ERROR_MAX = SGX_QL_MK_ERROR(
        0x00FF), ///< Indicate max error to allow better translation.
} quote3_error_t;

#undef SGX_QL_MK_ERROR

// END Intel-defiend types
//////////////////////////////////////////////////////////////////////////////

quote3_error_t sgx_ql_get_quote_config(
    sgx_ql_pck_cert_id_t* p_pck_cert_id,
    const sgx_ql_config_t* p_quote_config);

/*****************************************************************************
 * Data types and interfaces for getting platform revocation info. This
 * includes fetching CRLs as well as the Intel-defined TCB info.
 ****************************************************************************/
typedef enum _sgx_ql_revocation_info_version_t {
    SGX_QL_REVOCATION_INFO_VERSION_1 = 1
} sgx_ql_revocation_info_version_t;

typedef struct _sgx_ql_get_revocation_info_params_t
{
    sgx_ql_revocation_info_version_t version;
    uint32_t fmspc_size;  // size of fmspc
    const uint8_t* fmspc; // Family-Model-Stepping-Platform-Custom
} sgx_ql_get_revocation_info_params_t;

typedef struct _sgx_ql_revocation_info_t
{
    sgx_ql_revocation_info_version_t version;

    uint32_t tcb_info_size;         // size of tcb_info
    uint8_t* tcb_info;              // Intel-signed TCB info structure
    uint32_t tcb_issuer_chain_size; // size of issuer chain for TCB info
    uint8_t* tcb_issuer_chain;      // PEM-encoded certificate chain

    uint32_t crl_data_size;         // size of crl_data
    uint8_t* crl_data;              // RFC 5280 CRL
    uint32_t crl_issuer_chain_size; // size of issuer chain for the CRL
    uint8_t* crl_issuer_chain;      // PEM-encoded certificate chain
} sgx_ql_revocation_info_t;

quote3_error_t sgx_ql_get_revocation_info(
    const sgx_ql_get_revocation_info_params_t* params,
    sgx_ql_revocation_info_t** pp_revocation_info);

void sgx_ql_free_revocation_info(sgx_ql_revocation_info_t* p_revocation_info);

/*****************************************************************************
 * Data types and interfaces for configuration the platform quote provider
 * library.
 ****************************************************************************/
typedef enum _sgx_ql_log_level_t {
    SGX_QL_LOG_ERROR,
    SGX_QL_LOG_INFO
} sgx_ql_log_level_t;

/// Function signature used for logging from within the library
typedef void (
    *sgx_ql_logging_function_t)(sgx_ql_log_level_t level, const char* message);

/// Set the callback used for recording log information.
quote3_error_t sgx_ql_set_logging_function(sgx_ql_logging_function_t logger);

/// Set the base URL for the certificate host service. This is typically done
/// for testing.
quote3_error_t sgx_ql_set_base_url(const char* url);
// ReSharper enable CppInconsistentNaming