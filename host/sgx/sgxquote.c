// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgxquote.h"
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_ql_lib_common.h>
#include <sgx_quote_3.h>
#include <sgx_uae_quote_ex.h>
#include <stdlib.h>
#include <string.h>
#include "../../common/oe_host_stdlib.h"
#include "../dupenv.h"
#include "../hostthread.h"
#include "sgxquote_ex.h"

// Check consistency with OE definition.
OE_STATIC_ASSERT(sizeof(sgx_target_info_t) == 512);
OE_STATIC_ASSERT(sizeof(sgx_report_t) == 432);

static const oe_uuid_t _sgx_ecdsa_p256_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _tdx_ecdsa_p256_uuid = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};

OE_STATIC_ASSERT(sizeof(sgx_att_key_id_ext_t) == sizeof(sgx_att_key_id_t));

// Redefine some constants in <sgx_quote_3.h> to be more meaningful
#define SGX_QL_ALG_EPID_UNLINKABLE SGX_QL_ALG_EPID
#define SGX_QL_ALG_EPID_LINKABLE SGX_QL_ALG_RESERVED_1

// Redefine the collateral version string for TDX collateral
#define SGX_QL_QVE_COLLATERAL_VERSION_3_0 (0x00000003)
#define SGX_QL_QVE_COLLATERAL_VERSION_3_1 (0x00010003)
#define SGX_QL_QVE_COLLATERAL_VERSION_4_0 (0x00000004)

// Facilitate writing switch statement for quote3_error_t and sgx_status_t
// values
#define CASE_ERROR_RETURN_ERROR_STRING(x) \
    case x:                               \
        return #x;

static oe_sgx_quote_ex_library_t _quote_ex_library = {0};
static const oe_uuid_t _unknown_uuid = {OE_FORMAT_UUID_SGX_UNKNOWN};
static const oe_uuid_t _epid_linkable_uuid = {OE_FORMAT_UUID_SGX_EPID_LINKABLE};
static const oe_uuid_t _epid_unlinkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_UNLINKABLE};

static sgx_att_key_id_ext_t* _format_id_to_key_id(const oe_uuid_t* format_id)
{
    if (!format_id)
        return NULL;

    for (size_t i = 0; i < _quote_ex_library.key_id_count; i++)
    {
        if (!_quote_ex_library.mapped[i])
            continue;

        if (!memcmp(format_id, _quote_ex_library.uuid + i, sizeof(oe_uuid_t)))
            return _quote_ex_library.sgx_key_id + i;
    }

    return NULL;
}

static quote3_error_t (*_sgx_qe_get_target_info)(
    sgx_target_info_t* p_qe_target_info);

static quote3_error_t (*_sgx_qe_get_quote_size)(uint32_t* p_quote_size);

static quote3_error_t (*_sgx_qe_get_quote)(
    const sgx_report_t* p_app_report,
    uint32_t quote_size,
    uint8_t* p_quote);

static quote3_error_t (*_sgx_qv_set_enclave_load_policy)(
    sgx_ql_request_policy_t policy);

static quote3_error_t (*_sgx_qv_get_quote_supplemental_data_size)(
    uint32_t* p_data_size);

static quote3_error_t (*_sgx_qv_verify_quote)(
    const uint8_t* p_quote,
    uint32_t quote_size,
    const struct _sgx_ql_qve_collateral_t* p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    sgx_ql_qv_result_t* p_quote_verification_result,
    sgx_ql_qe_report_info_t* p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t* p_supplemental_data);

static quote3_error_t (*_tee_get_supplemental_data_version_and_size)(
    const uint8_t* p_quote,
    uint32_t quote_size,
    uint32_t* p_version,
    uint32_t* p_data_size);

static quote3_error_t (*_tee_verify_quote)(
    const uint8_t* p_quote,
    uint32_t quote_size,
    const tdx_ql_qve_collateral_t* p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    sgx_ql_qv_result_t* p_quote_verification_result,
    sgx_ql_qe_report_info_t* p_qve_report_info,
    uint8_t* p_supp_data_descriptor);

static quote3_error_t (*_tee_qv_get_collateral)(
    const uint8_t* p_quote,
    uint32_t quote_size,
    uint8_t** pp_quote_collateral,
    uint32_t* p_collateral_size);

static quote3_error_t (*_tee_qv_free_collateral)(uint8_t* p_quote_collateral);

static sgx_ql_request_policy_t _policy = SGX_QL_DEFAULT;

typedef struct _supp_ver_t
{
    uint16_t major_version;
    uint16_t minor_version;
} supp_ver_t;

#ifdef _WIN32

#include <windows.h>

#define SGX_DCAP_QL_NAME "sgx_dcap_ql.dll"
#define SGX_DCAP_QVL_NAME "sgx_dcap_quoteverify.dll"

#define LOAD_SGX_DCAP_LIB(libname) \
    (void*)LoadLibraryEx(          \
        (LPCSTR)libname, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

#define LOOKUP_FUNCTION(module, fcn) (void*)GetProcAddress((HANDLE)module, fcn)

#define UNLOAD_SGX_DCAP_LIB(module) FreeLibrary((HANDLE)module)

#define SGX_DCAP_IN_PROCESS_QUOTING() \
    (GetEnvironmentVariableA("SGX_AESM_ADDR", NULL, 0) == 0)

#define TRY_TO_USE_SGX_DCAP_QVL() \
    (GetEnvironmentVariableA("USE_SGX_QVL", NULL, 0) != 0)

#else

#include <dlfcn.h>

#define SGX_DCAP_QL_NAME "libsgx_dcap_ql.so.1"
#define SGX_DCAP_QVL_NAME "libsgx_dcap_quoteverify.so.1"

// Use best practices
// - RTLD_NOW  Bind all undefined symbols before dlopen returns.
// - RTLD_GLOBAL Make symbols from this shared library visible to
//   subsequently loaded libraries.
#define LOAD_SGX_DCAP_LIB(libname) dlopen(libname, RTLD_NOW | RTLD_GLOBAL)

#define LOOKUP_FUNCTION(module, fcn) (void*)dlsym(module, fcn)

#define UNLOAD_SGX_DCAP_LIB(module) dlclose(module)

#define SGX_DCAP_IN_PROCESS_QUOTING() (getenv("SGX_AESM_ADDR") == NULL)

#define TRY_TO_USE_SGX_DCAP_QVL() (getenv("USE_SGX_QVL") != NULL)

#define sprintf_s(buffer, size, format, argument) \
    sprintf(buffer, format, argument)

#endif

static void* _ql_module;
static void* _qvl_module;

// Starting from
// https://github.com/intel/SGXDataCenterAttestationPrimitives/releases/tag/DCAP_1.18
// The API (sgx_qv_set_enclave_load_policy) is enhanced to support changing QvL
// multithreading behavior At runtime, OE read env var
// "OE_INTEL_QVL_LOAD_POLICY=?" to set sgx_ql_request_policy_t policy Accepted
// values: SGX_QL_PERSISTENT, SGX_QL_EPHEMERAL,
// SGX_QL_EPHEMERAL_QVE_MULTI_THREAD, SGX_QL_PERSISTENT_QVE_MULTI_THREAD,
// SGX_QL_DEFAULT
static sgx_ql_request_policy_t _get_qvl_load_policy(void)
{
    sgx_ql_request_policy_t policy = SGX_QL_DEFAULT;
    char* policy_str = oe_dupenv("OE_INTEL_QVL_LOAD_POLICY");

    if (policy_str == NULL)
    {
        goto done;
    }
    else if (strcmp(policy_str, "SGX_QL_PERSISTENT") == 0)
    {
        policy = SGX_QL_PERSISTENT;
    }
    else if (strcmp(policy_str, "SGX_QL_EPHEMERAL") == 0)
    {
        policy = SGX_QL_EPHEMERAL;
    }
    else if (strcmp(policy_str, "SGX_QL_EPHEMERAL_QVE_MULTI_THREAD") == 0)
    {
        policy = SGX_QL_EPHEMERAL_QVE_MULTI_THREAD;
    }
    else if (strcmp(policy_str, "SGX_QL_PERSISTENT_QVE_MULTI_THREAD") == 0)
    {
        policy = SGX_QL_PERSISTENT_QVE_MULTI_THREAD;
    }
    else if (strcmp(policy_str, "SGX_QL_DEFAULT") == 0)
    {
        policy = SGX_QL_DEFAULT;
    }
done:
    if (policy_str)
        free(policy_str);

    return policy;
}

// This is a helper for getting human readable quote3_error_t codes.
static const char* get_quote3_error_t_string(quote3_error_t error)
{
    switch (error)
    {
        // all possible quote3_error_t error codes
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_UNEXPECTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_INVALID_PARAMETER);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_OUT_OF_MEMORY);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_ECDSA_ID_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_FILE_ACCESS_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_STORED_KEY);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_PUB_KEY_ID_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ATT_KEY_BLOB_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNSUPPORTED_ATT_KEY_ID);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNSUPPORTED_LOADING_POLICY);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_INTERFACE_UNAVAILABLE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PLATFORM_LIB_UNAVAILABLE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ATT_KEY_NOT_INITIALIZED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ATT_KEY_CERT_DATA_INVALID);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_NO_PLATFORM_CERT_DATA);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_OUT_OF_EPC);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_REPORT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ENCLAVE_LOST);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_INVALID_REPORT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ENCLAVE_LOAD_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNABLE_TO_GENERATE_QE_REPORT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_KEY_CERTIFCATION_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_NETWORK_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_MESSAGE_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_NO_QUOTE_COLLATERAL_DATA);
        CASE_ERROR_RETURN_ERROR_STRING(
            SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QUOTE_FORMAT_UNSUPPORTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNABLE_TO_GENERATE_REPORT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QE_REPORT_INVALID_SIGNATURE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PCK_CERT_CHAIN_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCBINFO_UNSUPPORTED_FORMAT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCBINFO_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QEIDENTITY_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCB_OUT_OF_DATE);
        CASE_ERROR_RETURN_ERROR_STRING(
            SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE);
        CASE_ERROR_RETURN_ERROR_STRING(
            SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QE_IDENTITY_OUT_OF_DATE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SGX_TCB_INFO_EXPIRED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SGX_CRL_EXPIRED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PCK_REVOKED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCB_REVOKED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCB_CONFIGURATION_NEEDED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNABLE_TO_GET_COLLATERAL);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_INVALID_PRIVILEGE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_NO_QVE_IDENTITY_DATA);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_CRL_UNSUPPORTED_FORMAT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QEIDENTITY_CHAIN_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCBINFO_CHAIN_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_QVL_QVE_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCB_SW_HARDENING_NEEDED);
        CASE_ERROR_RETURN_ERROR_STRING(
            SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNSUPPORTED_MODE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_NO_DEVICE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SERVICE_UNAVAILABLE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_NETWORK_FAILURE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_SERVICE_TIMEOUT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_BUSY);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNKNOWN_MESSAGE_RESPONSE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PERSISTENT_STORAGE_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ERROR_MESSAGE_PARSING_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PLATFORM_UNKNOWN);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_UNKNOWN_API_VERSION);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_CERTS_UNAVAILABLE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QVEIDENTITY_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QVE_OUT_OF_DATE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_PSW_NOT_AVAILABLE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TDX_MODULE_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_QEIDENTITY_NOT_FOUND);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCBINFO_NOT_FOUND);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_INTERNAL_SERVER_ERROR);
        CASE_ERROR_RETURN_ERROR_STRING(
            SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_ROOT_CA_UNTRUSTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_QL_TCB_NOT_SUPPORTED);

        // return the error number as is in the default case
        default:
        {
            static char quote3_error_t_hex[16];
            sprintf_s(
                quote3_error_t_hex, sizeof(quote3_error_t_hex), "0x%x", error);
            return quote3_error_t_hex;
        }
    }
}

// This is a helper for getting "human readable sgx status".
static const char* get_sgx_status_t_string(sgx_status_t status)
{
    switch (status)
    {
        // all possible sgx_status_t error codes
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_UNEXPECTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_PARAMETER);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_OUT_OF_MEMORY);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_ENCLAVE_LOST);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_STATE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FEATURE_NOT_SUPPORTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_PTHREAD_EXIT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_FUNCTION);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_OUT_OF_TCS);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_ENCLAVE_CRASHED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_ECALL_NOT_ALLOWED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_OCALL_NOT_ALLOWED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_STACK_OVERRUN);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_UNDEFINED_SYMBOL);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_ENCLAVE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_ENCLAVE_ID);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_SIGNATURE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_NDEBUG_ENCLAVE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_OUT_OF_EPC);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_NO_DEVICE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_MEMORY_MAP_CONFLICT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_METADATA);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_DEVICE_BUSY);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_VERSION);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_MODE_INCOMPATIBLE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_ENCLAVE_FILE_ACCESS);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_MISC);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_LAUNCH_TOKEN);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_MAC_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_ATTRIBUTE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_CPUSVN);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_ISVSVN);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_KEYNAME);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_SERVICE_UNAVAILABLE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_SERVICE_TIMEOUT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_AE_INVALID_EPIDBLOB);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_SERVICE_INVALID_PRIVILEGE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_EPID_MEMBER_REVOKED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_UPDATE_NEEDED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_NETWORK_FAILURE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_AE_SESSION_INVALID);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_BUSY);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_MC_NOT_FOUND);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_MC_NO_ACCESS_RIGHT);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_MC_USED_UP);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_MC_OVER_QUOTA);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_KDF_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_UNRECOGNIZED_PLATFORM);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_UNSUPPORTED_CONFIG);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_NO_PRIVILEGE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_PCL_ENCRYPTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_PCL_NOT_ENCRYPTED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_PCL_MAC_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_PCL_SHA_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_PCL_GUID_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_BAD_STATUS);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_NO_KEY_ID);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_NAME_MISMATCH);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_NOT_SGX_FILE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_RECOVERY_NEEDED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_FLUSH_FAILED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_FILE_CLOSE_FAILED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_UNSUPPORTED_ATT_KEY_ID);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_ATT_KEY_UNINITIALIZED);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_INVALID_ATT_KEY_CERT_DATA);
        CASE_ERROR_RETURN_ERROR_STRING(SGX_ERROR_PLATFORM_CERT_UNAVAILABLE);
        CASE_ERROR_RETURN_ERROR_STRING(
            SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED);

        // return the error number as is in the default case
        default:
        {
            static char sgx_status_t_hex[16];
            sprintf_s(
                sgx_status_t_hex, sizeof(sgx_status_t_hex), "0x%x", status);
            return sgx_status_t_hex;
        }
    }
}

static oe_result_t get_oe_result_t(quote3_error_t error)
{
    switch (error)
    {
        case SGX_QL_SUCCESS:
        case SGX_QL_TCB_SW_HARDENING_NEEDED:
        case SGX_QL_SGX_TCB_INFO_EXPIRED:
            return OE_OK;

        case SGX_QL_ERROR_INVALID_PARAMETER:
            return OE_INVALID_PARAMETER;

        case SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT:
        case SGX_QL_PCK_CERT_CHAIN_ERROR:
        case SGX_QL_TCBINFO_UNSUPPORTED_FORMAT:
        case SGX_QL_TCBINFO_CHAIN_ERROR:
        case SGX_QL_TCBINFO_MISMATCH:
        case SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT:
        case SGX_QL_QEIDENTITY_CHAIN_ERROR:
        case SGX_QL_TCB_OUT_OF_DATE:
        case SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
        case SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
        case SGX_QL_QE_IDENTITY_OUT_OF_DATE:
        case SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED:
        case SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED:
        case SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED:
        case SGX_QL_QEIDENTITY_NOT_FOUND:
        case SGX_QL_NO_QVE_IDENTITY_DATA:
            return OE_INVALID_ENDORSEMENT;

        case SGX_QL_QUOTE_FORMAT_UNSUPPORTED:
        case SGX_QL_QE_REPORT_INVALID_SIGNATURE:
        case SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT:
        case SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED:
            return OE_QUOTE_VERIFICATION_ERROR;

        case SGX_QL_SGX_CRL_EXPIRED:
            return OE_VERIFY_CRL_EXPIRED;

        case SGX_QL_PCK_REVOKED:
        case SGX_QL_TCB_REVOKED:
            return OE_VERIFY_REVOKED;

        case SGX_QL_TCB_CONFIGURATION_NEEDED:
        case SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        case SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        case SGX_QL_TCBINFO_NOT_FOUND:
        case SGX_QL_TCB_NOT_SUPPORTED:
            return OE_TCB_LEVEL_INVALID;

        default:
            return OE_UNEXPECTED;
    }
}

static void _unload_sgx_dcap_ql(void)
{
    if (_ql_module)
    {
        UNLOAD_SGX_DCAP_LIB(_ql_module);
        _ql_module = NULL;
    }
}

static void _unload_sgx_dcap_qvl(void)
{
    if (_qvl_module)
    {
        UNLOAD_SGX_DCAP_LIB(_qvl_module);
        _qvl_module = NULL;
    }
}

static oe_result_t _lookup_function(
    const void* module,
    const char* name,
    void** function_ptr)
{
    oe_result_t result = OE_FAILURE;
    *function_ptr = LOOKUP_FUNCTION((void*)(module), name);
    if (!*function_ptr)
    {
        OE_TRACE_ERROR("%s function not found.\n", name);
        goto done;
    }
    result = OE_OK;
done:
    return result;
}

static void _load_sgx_dcap_ql_impl(void)
{
    oe_result_t result = OE_FAILURE;
    OE_TRACE_INFO("Loading %s\n", SGX_DCAP_QL_NAME);
    _ql_module = LOAD_SGX_DCAP_LIB(SGX_DCAP_QL_NAME);

    if (_ql_module)
    {
        OE_CHECK(_lookup_function(
            _ql_module,
            "sgx_qe_get_target_info",
            (void**)&_sgx_qe_get_target_info));
        OE_CHECK(_lookup_function(
            _ql_module,
            "sgx_qe_get_quote_size",
            (void**)&_sgx_qe_get_quote_size));
        OE_CHECK(_lookup_function(
            _ql_module, "sgx_qe_get_quote", (void**)&_sgx_qe_get_quote));

        atexit(_unload_sgx_dcap_ql);
        result = OE_OK;
        OE_TRACE_INFO("Loaded %s\n", SGX_DCAP_QL_NAME);
    }
    else
    {
        OE_TRACE_WARNING("Failed to load %s\n", SGX_DCAP_QL_NAME);
        goto done;
    }

done:
    if (result != OE_OK)
    {
        OE_TRACE_WARNING("Alternative quoting library will be needed.");
    }
}

static bool _load_sgx_dcap_ql(void)
{
    static oe_once_type _once;
    oe_once(&_once, _load_sgx_dcap_ql_impl);
    return (_ql_module != NULL);
}

/* Load QVL functions for TDX separately so that
 * we can still make QVL optional for SGX */
static void _load_tdx_dcap_qvl_impl(void)
{
    oe_result_t result = OE_FAILURE;
    OE_TRACE_INFO("Loading %s for TDX\n", SGX_DCAP_QVL_NAME);
    _qvl_module = LOAD_SGX_DCAP_LIB(SGX_DCAP_QVL_NAME);

    if (_qvl_module)
    {
        OE_CHECK(_lookup_function(
            _qvl_module,
            "sgx_qv_set_enclave_load_policy",
            (void**)&_sgx_qv_set_enclave_load_policy));
        OE_CHECK(_lookup_function(
            _qvl_module,
            "tee_get_supplemental_data_version_and_size",
            (void**)&_tee_get_supplemental_data_version_and_size));
        OE_CHECK(_lookup_function(
            _qvl_module, "tee_verify_quote", (void**)&_tee_verify_quote));
        OE_CHECK(_lookup_function(
            _qvl_module,
            "tee_qv_get_collateral",
            (void**)&_tee_qv_get_collateral));
        OE_CHECK(_lookup_function(
            _qvl_module,
            "tee_qv_free_collateral",
            (void**)&_tee_qv_free_collateral));
        result = OE_OK;
    }
    else
    {
        OE_TRACE_WARNING("Failed to load %s\n", SGX_DCAP_QVL_NAME);
        goto done;
    }

done:
    if (result != OE_OK)
    {
        OE_TRACE_WARNING(
            "Alternative TDX quote verification library will be needed.");
    }
}

static bool _load_tdx_dcap_qvl(void)
{
    static oe_once_type _once;
    oe_once(&_once, _load_tdx_dcap_qvl_impl);

    {
        sgx_ql_request_policy_t new_policy = _get_qvl_load_policy();
        // Only call set_policy on policy change
        if (new_policy != _policy)
        {
            quote3_error_t error = _sgx_qv_set_enclave_load_policy(new_policy);
            if (error != SGX_QL_SUCCESS)
            {
                OE_TRACE_ERROR(
                    "_sgx_qv_set_enclave_load_policy failed with "
                    "quote3_error_t=%s\n",
                    get_quote3_error_t_string(error));
            }

            _policy = new_policy;
        }
    }

    return (_qvl_module != NULL);
}

static void _load_sgx_dcap_qvl_impl(void)
{
    oe_result_t result = OE_FAILURE;
    OE_TRACE_INFO("Loading %s\n", SGX_DCAP_QVL_NAME);
    _qvl_module = LOAD_SGX_DCAP_LIB(SGX_DCAP_QVL_NAME);

    if (_qvl_module)
    {
        OE_CHECK(_lookup_function(
            _qvl_module,
            "sgx_qv_set_enclave_load_policy",
            (void**)&_sgx_qv_set_enclave_load_policy));
        OE_CHECK(_lookup_function(
            _qvl_module,
            "sgx_qv_get_quote_supplemental_data_size",
            (void**)&_sgx_qv_get_quote_supplemental_data_size));
        OE_CHECK(_lookup_function(
            _qvl_module, "sgx_qv_verify_quote", (void**)&_sgx_qv_verify_quote));

        atexit(_unload_sgx_dcap_qvl);
        result = OE_OK;
        OE_TRACE_INFO("Loaded %s\n", SGX_DCAP_QVL_NAME);
    }
    else
    {
        OE_TRACE_WARNING("Failed to load %s\n", SGX_DCAP_QVL_NAME);
        goto done;
    }

done:
    if (result != OE_OK)
    {
        OE_TRACE_WARNING(
            "Alternative SGX quote verification library will be needed.");
    }
}

static bool _load_sgx_dcap_qvl(void)
{
    static oe_once_type _once;
    oe_once(&_once, _load_sgx_dcap_qvl_impl);

    {
        sgx_ql_request_policy_t new_policy = _get_qvl_load_policy();
        // Only call set_policy on policy change
        if (new_policy != _policy)
        {
            quote3_error_t error = _sgx_qv_set_enclave_load_policy(new_policy);
            if (error != SGX_QL_SUCCESS)
            {
                OE_TRACE_ERROR(
                    "_sgx_qv_set_enclave_load_policy failed with "
                    "quote3_error_t=%s\n",
                    get_quote3_error_t_string(error));
            }

            _policy = new_policy;
        }
    }

    return (_qvl_module != NULL);
}

static void _load_quote_ex_library_once(void)
{
    bool* local_mapped = NULL;
    oe_uuid_t* local_uuid = NULL;
    sgx_att_key_id_ext_t* local_key_id = NULL;
    oe_result_t result = OE_UNEXPECTED;

    // First test if DCAP in-process quoting is requested.
    // If not, there is no need to load DCAP without using it.
    if (SGX_DCAP_IN_PROCESS_QUOTING() && _load_sgx_dcap_ql())
    {
        OE_TRACE_INFO("DCAP installed and set for in-process quoting.");
        _quote_ex_library.use_dcap_library_instead = true;
        return;
    }
    else
    {
        OE_TRACE_INFO(
            "DCAP not installed or set for out-of-process, try quote-ex");
        _quote_ex_library.use_dcap_library_instead = false;
    }

    if (_quote_ex_library.handle && _quote_ex_library.load_result == OE_OK)
        return;

    oe_sgx_load_quote_ex_library(&_quote_ex_library);
    if (_quote_ex_library.load_result == OE_OK)
    {
        uint32_t att_key_id_num = 0;
        uint32_t mapped_key_id_count = 0;
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        status =
            _quote_ex_library.sgx_get_supported_att_key_id_num(&att_key_id_num);

        if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
            OE_RAISE_MSG(
                OE_SERVICE_UNAVAILABLE, "SGX AESM service unavailable", NULL);

        if (status != SGX_SUCCESS || att_key_id_num == 0)
            OE_RAISE_MSG(
                OE_SGX_QUOTE_LIBRARY_ERROR,
                "SGX quote-ex failure: _load_quote_ex_library_once() "
                "sgx_get_supported_att_key_id_num() status=%s num=%d\n",
                get_sgx_status_t_string(status),
                att_key_id_num);

        local_mapped = (bool*)oe_malloc(att_key_id_num * sizeof(bool));
        local_uuid = (oe_uuid_t*)oe_malloc(att_key_id_num * sizeof(oe_uuid_t));
        local_key_id = (sgx_att_key_id_ext_t*)oe_malloc(
            att_key_id_num * sizeof(sgx_att_key_id_ext_t));

        if (!local_mapped || !local_uuid || !local_key_id)
            OE_RAISE(OE_OUT_OF_MEMORY);

        status = _quote_ex_library.sgx_get_supported_att_key_ids(
            local_key_id, att_key_id_num);

        if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
            OE_RAISE_MSG(
                OE_SERVICE_UNAVAILABLE, "SGX AESM service unavailable", NULL);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_SGX_QUOTE_LIBRARY_ERROR,
                "SGX quote-ex failure: _load_quote_ex_library_once() "
                "sgx_get_supported_att_key_ids() status=%s\n",
                get_sgx_status_t_string(status));

        for (uint32_t i = 0; i < att_key_id_num; i++)
        {
            sgx_att_key_id_ext_t* key = local_key_id + i;
            const oe_uuid_t* uuid = NULL;

            OE_TRACE_INFO("algorithm_id=%d", key->base.algorithm_id);

            switch (key->base.algorithm_id)
            {
                case SGX_QL_ALG_EPID_UNLINKABLE:
                    uuid = &_epid_unlinkable_uuid;
                    local_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_EPID_LINKABLE:
                    uuid = &_epid_linkable_uuid;
                    local_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_ECDSA_P256:
                    uuid = &_sgx_ecdsa_p256_uuid;
                    local_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                default:
                    uuid = &_unknown_uuid;
                    local_mapped[i] = false;
                    OE_TRACE_ERROR(
                        "algorithm_id=%d maps to no uuid",
                        key->base.algorithm_id);
                    break;
            }
            memcpy(local_uuid + i, uuid, sizeof(oe_uuid_t));
        }

        _quote_ex_library.key_id_count = att_key_id_num;
        _quote_ex_library.mapped_key_id_count = mapped_key_id_count;
        _quote_ex_library.mapped = local_mapped;
        _quote_ex_library.uuid = local_uuid;
        _quote_ex_library.sgx_key_id = local_key_id;
        local_mapped = NULL;
        local_uuid = NULL;
        local_key_id = NULL;

        OE_TRACE_INFO(
            "key_id_count=%lu mapped=%lu\n",
            att_key_id_num,
            mapped_key_id_count);

        result = OE_OK;
    }

done:
    if (local_mapped)
    {
        oe_free(local_mapped);
        local_mapped = NULL;
    }
    if (local_uuid)
    {
        oe_free(local_uuid);
        local_uuid = NULL;
    }
    if (local_key_id)
    {
        oe_free(local_key_id);
        local_key_id = NULL;
    }
    if (_quote_ex_library.load_result == OE_OK)
        _quote_ex_library.load_result = result;

    OE_TRACE_INFO(
        "_load_quote_ex_library_once() result=%s\n",
        oe_result_str(_quote_ex_library.load_result));

    return;
}

// For choosing between the DCAP library and the quote-ex library for quote
// generation: the DCAP library is used if it can be loaded and is configured
// to do in-process quote generation. Otherwise, if the DCAP library can't
// be loaded or it is configured to do out-of-process quote generation,
// we will try to use the quote-ex library instead.
// Please refer to the design document SGX_QuoteEx_Integration.md for more
// information on how the quote-ex library is integrated.

static bool _use_quote_ex_library(void)
{
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, _load_quote_ex_library_once);

    return (
        (!_quote_ex_library.use_dcap_library_instead) &&
        _quote_ex_library.load_result == OE_OK);
}

oe_result_t oe_sgx_qe_get_target_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !target_info)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_use_quote_ex_library())
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};
        size_t local_size = 0;
        uint8_t* local_buffer = NULL;
        sgx_target_info_t local_target_info;

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params && opt_params_size == sizeof(key_id->spid))
                memcpy(updated_key_id.spid, opt_params, opt_params_size);
        }

        status = _quote_ex_library.sgx_init_quote_ex(
            (sgx_att_key_id_t*)&updated_key_id,
            &local_target_info,
            &local_size,
            NULL);

        if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
            OE_RAISE_MSG(
                OE_SERVICE_UNAVAILABLE, "SGX AESM service unavailable", NULL);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_SGX_QUOTE_LIBRARY_ERROR,
                "SGX quote-ex failure: sgx_init_quote_ex(NULL) returned %s\n",
                get_sgx_status_t_string(status));

        local_buffer = (uint8_t*)oe_malloc(local_size);
        if (!local_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);

        status = _quote_ex_library.sgx_init_quote_ex(
            (sgx_att_key_id_t*)&updated_key_id,
            &local_target_info,
            &local_size,
            local_buffer);
        oe_free(local_buffer);

        if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
            OE_RAISE_MSG(
                OE_SERVICE_UNAVAILABLE, "SGX AESM service unavailable", NULL);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_SGX_QUOTE_LIBRARY_ERROR,
                "SGX quote-ex failure: sgx_init_quote_ex(local_buffer) "
                "returned %s\n",
                get_sgx_status_t_string(status));

        memcpy(target_info, &local_target_info, sizeof(sgx_target_info_t));

        result = OE_OK;
    }
    // If DCAP in-process quoting is not requested, no need to load DCAP
    else if (!_quote_ex_library.use_dcap_library_instead)
    {
        OE_RAISE_MSG(
            _quote_ex_library.load_result,
            "Failed to load SGX quote-ex library\n",
            NULL);
    }
    else
    {
        _load_sgx_dcap_ql();

        if (!_sgx_qe_get_target_info)
            OE_RAISE_MSG(
                OE_QUOTE_LIBRARY_LOAD_ERROR,
                "Failed to access _sgx_qe_get_target_info from quote "
                "library\n",
                NULL);

        error = _sgx_qe_get_target_info((sgx_target_info_t*)target_info);
        if (error != SGX_QL_SUCCESS)
            OE_RAISE_MSG(
                get_oe_result_t(error),
                "_sgx_qe_get_target_info failed with quote3_error_t=%s\n",
                get_quote3_error_t_string(error));

        result = OE_OK;
    }

done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t local_quote_size = (uint32_t)*quote_size;
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_use_quote_ex_library())
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params && opt_params_size == sizeof(key_id->spid))
                memcpy(updated_key_id.spid, opt_params, opt_params_size);
        }

        status = _quote_ex_library.sgx_get_quote_size_ex(
            (const sgx_att_key_id_t*)&updated_key_id, &local_quote_size);

        if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
            OE_RAISE_MSG(
                OE_SERVICE_UNAVAILABLE, "SGX AESM service unavailable", NULL);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_SGX_QUOTE_LIBRARY_ERROR,
                "SGX quote-ex failure: sgx_get_quote_size_ex() returned %s\n",
                get_sgx_status_t_string(status));

        OE_TRACE_INFO("local_quote_size = %lu\n", local_quote_size);

        *quote_size = local_quote_size;
        result = OE_OK;
    }
    // If DCAP in-process quoting is not requested, no need to load DCAP
    else if (!_quote_ex_library.use_dcap_library_instead)
    {
        OE_RAISE_MSG(
            _quote_ex_library.load_result,
            "Failed to use SGX quote-ex library\n",
            NULL);
    }
    else
    {
        _load_sgx_dcap_ql();

        if (!_sgx_qe_get_quote_size)
            OE_RAISE_MSG(
                OE_QUOTE_LIBRARY_LOAD_ERROR,
                "Failed to access _sgx_qe_get_quote_size from quote library\n",
                NULL);

        error = _sgx_qe_get_quote_size(&local_quote_size);

        if (error != SGX_QL_SUCCESS)
            OE_RAISE_MSG(
                get_oe_result_t(error),
                "_sgx_qe_get_quote_size failed with quote3_error_t=%s\n",
                get_quote3_error_t_string(error));

        *quote_size = local_quote_size;
        result = OE_OK;
    }
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report,
    size_t quote_size,
    uint8_t* quote)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t local_quote_size = (uint32_t)quote_size;
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !report || !quote || !quote_size ||
        quote_size > OE_MAX_UINT32)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_use_quote_ex_library())
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params)
            {
                if (opt_params_size == sizeof(key_id->spid))
                    memcpy(updated_key_id.spid, opt_params, opt_params_size);
                else
                {
                    OE_TRACE_INFO(
                        "EPID requires opt_params to be 16-byte SPID");
                    OE_RAISE(OE_INVALID_PARAMETER);
                }
            }
        }
        else // ECDSA
        {
            // For ECDSA, opt_params_size should be zero.
            if (opt_params || opt_params_size)
                OE_RAISE(OE_INVALID_PARAMETER);
        }

        status = _quote_ex_library.sgx_get_quote_ex(
            (const sgx_report_t*)report,
            (const sgx_att_key_id_t*)&updated_key_id,
            NULL,
            quote,
            local_quote_size);

        if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
            OE_RAISE_MSG(
                OE_SERVICE_UNAVAILABLE, "SGX AESM service unavailable", NULL);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_SGX_QUOTE_LIBRARY_ERROR,
                "SGX quote-ex failure: sgx_get_quote_ex() returned %s\n",
                get_sgx_status_t_string(status));

        OE_TRACE_INFO(
            "quote_ex got quote for algorithm_id=%d\n",
            key_id->base.algorithm_id);

        result = OE_OK;
    }
    // If DCAP in-process quoting is not requested, no need to load DCAP
    else if (!_quote_ex_library.use_dcap_library_instead)
    {
        OE_RAISE_MSG(
            _quote_ex_library.load_result,
            "Failed to use SGX quote-ex library\n",
            NULL);
    }
    else
    {
        // Only ECDSA is supported, opt_params_size should be zero.
        if (opt_params || opt_params_size)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (quote_size > OE_MAX_UINT32)
            OE_RAISE(OE_INVALID_PARAMETER);

        local_quote_size = (uint32_t)quote_size;

        if (_load_sgx_dcap_ql())
        {
            if (!_sgx_qe_get_quote)
                OE_RAISE_MSG(
                    OE_QUOTE_LIBRARY_LOAD_ERROR,
                    "Failed to access _sgx_qe_get_quote from quote library\n",
                    NULL);

            error = _sgx_qe_get_quote(
                (sgx_report_t*)report, local_quote_size, quote);
            if (error != SGX_QL_SUCCESS)
                OE_RAISE_MSG(
                    get_oe_result_t(error),
                    "_sgx_qe_get_quote failed quote3_error_t=%s\n",
                    get_quote3_error_t_string(error));
            OE_TRACE_INFO("quote_size=%d", local_quote_size);

            result = OE_OK;
        }
        else
            // Failed to load DCAP QL library
            result = OE_PLATFORM_ERROR;
    }
done:
    return result;
}

oe_result_t oe_sgx_get_supported_attester_format_ids(
    void** format_ids_data,
    size_t* format_ids_size)
{
    oe_result_t result = OE_UNEXPECTED;
    void* data = NULL;
    size_t size = 0;

    if (!format_ids_data || !format_ids_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    *format_ids_data = NULL;
    *format_ids_size = 0;

    if (_use_quote_ex_library())
    {
        size_t count = _quote_ex_library.mapped_key_id_count;
        size_t index = 0;

        size = sizeof(oe_uuid_t) * count;
        OE_TRACE_INFO("quote_ex got %lu format IDs\n", count);
        if (!count)
        {
            result = OE_OK;
            goto done;
        }

        data = malloc(size);
        if (!data)
            OE_RAISE(OE_OUT_OF_MEMORY);

        for (size_t i = 0; i < _quote_ex_library.key_id_count; i++)
        {
            // Skip the entry if it was not mapped.
            if (!_quote_ex_library.mapped[i])
                continue;

            memcpy(
                ((uint8_t*)data) + sizeof(oe_uuid_t) * index,
                _quote_ex_library.uuid + i,
                sizeof(oe_uuid_t));
            index++;
        }
    }
    else if (!_quote_ex_library.use_dcap_library_instead)
    {
        OE_RAISE_MSG(
            _quote_ex_library.load_result,
            "Failed to use SGX quote-ex library\n",
            NULL);
    }
    else
    {
        // Case when DCAP is used
        size = sizeof(oe_uuid_t);
        data = malloc(size);
        if (!data)
            OE_RAISE(OE_OUT_OF_MEMORY);

        memcpy(data, &_sgx_ecdsa_p256_uuid, sizeof(oe_uuid_t));
        *format_ids_size = sizeof(oe_uuid_t);

        OE_TRACE_INFO("DCAP only supports ECDSA_P256\n");
    }

    *format_ids_data = data;
    *format_ids_size = size;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_get_supplemental_data_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint32_t* supplemental_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;
    uint32_t local_data_size = 0;

    // Add format_id for forward compatibility
    // Only support ECDSA-p256 now
    if (memcmp(
            format_id, &_sgx_ecdsa_p256_uuid, sizeof(_sgx_ecdsa_p256_uuid)) !=
        0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!supplemental_data_size || (!opt_params && opt_params_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (TRY_TO_USE_SGX_DCAP_QVL() && _load_sgx_dcap_qvl())
    {
        error = _sgx_qv_get_quote_supplemental_data_size(&local_data_size);
        if (error != SGX_QL_SUCCESS)
            OE_RAISE_MSG(
                get_oe_result_t(error),
                "_sgx_qv_get_quote_supplemental_data_size failed with "
                "quote3_error_t=%s\n",
                get_quote3_error_t_string(error));

        *supplemental_data_size = local_data_size;
        result = OE_OK;
    }
    else
        // Failed to load DCAP QVL library
        result = OE_PLATFORM_ERROR;

done:
    return result;
}

oe_result_t oe_sgx_verify_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const uint8_t* p_quote,
    uint32_t quote_size,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size)
{
    oe_result_t result = OE_UNEXPECTED;
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;

    // Input validation
    // Add format_id for forward compatibility
    // Only support ECDSA-p256 now
    if (memcmp(
            format_id, &_sgx_ecdsa_p256_uuid, sizeof(_sgx_ecdsa_p256_uuid)) !=
        0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!p_quote || quote_size > OE_MAX_UINT32 ||
        !p_collateral_expiration_status || !p_quote_verification_result)
        OE_RAISE(OE_INVALID_PARAMETER);

    if ((!opt_params && opt_params_size > 0) ||
        (!p_qve_report_info && qve_report_info_size > 0) ||
        (!p_supplemental_data && supplemental_data_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (p_qve_report_info &&
        qve_report_info_size != sizeof(sgx_ql_qe_report_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);
    // End of Input validation

    if (TRY_TO_USE_SGX_DCAP_QVL() && _load_sgx_dcap_qvl())
    {
        sgx_ql_qve_collateral_t* p_sgx_endorsements = NULL;

        // If user provide OE endorsements buffer, try to use it
        if (p_tcb_info && tcb_info_size > 0 && p_tcb_info_issuer_chain &&
            tcb_info_size > 0 && p_pck_crl && pck_crl_size > 0 &&
            p_root_ca_crl && root_ca_crl_size > 0 && p_pck_crl_issuer_chain &&
            pck_crl_issuer_chain_size > 0 && p_qe_identity &&
            qe_identity_size > 0 && p_qe_identity_issuer_chain &&
            qe_identity_issuer_chain_size > 0)
        {
            p_sgx_endorsements = (sgx_ql_qve_collateral_t*)oe_malloc(
                sizeof(sgx_ql_qve_collateral_t));
            if (p_sgx_endorsements == NULL)
            {
                OE_RAISE_MSG(
                    OE_OUT_OF_MEMORY,
                    "Out of memory while creating SGX QVL endorsements.",
                    NULL);
            }
            memset(p_sgx_endorsements, 0, sizeof(sgx_ql_qve_collateral_t));

            p_sgx_endorsements->version = collateral_version;
            p_sgx_endorsements->tcb_info = (char*)p_tcb_info;
            p_sgx_endorsements->tcb_info_size = tcb_info_size;
            p_sgx_endorsements->tcb_info_issuer_chain =
                (char*)p_tcb_info_issuer_chain;
            p_sgx_endorsements->tcb_info_issuer_chain_size =
                tcb_info_issuer_chain_size;
            p_sgx_endorsements->pck_crl = (char*)p_pck_crl;
            p_sgx_endorsements->pck_crl_size = pck_crl_size;
            p_sgx_endorsements->root_ca_crl = (char*)p_root_ca_crl;
            p_sgx_endorsements->root_ca_crl_size = root_ca_crl_size;
            p_sgx_endorsements->pck_crl_issuer_chain =
                (char*)p_pck_crl_issuer_chain;
            p_sgx_endorsements->pck_crl_issuer_chain_size =
                pck_crl_issuer_chain_size;
            p_sgx_endorsements->qe_identity = (char*)p_qe_identity;
            p_sgx_endorsements->qe_identity_size = qe_identity_size;
            p_sgx_endorsements->qe_identity_issuer_chain =
                (char*)p_qe_identity_issuer_chain;
            p_sgx_endorsements->qe_identity_issuer_chain_size =
                qe_identity_issuer_chain_size;

            OE_TRACE_INFO("SGX endorsements from OE SDK are used for quote "
                          "verification\n");
        }

        error = _sgx_qv_verify_quote(
            p_quote,
            (uint32_t)quote_size,
            p_sgx_endorsements,
            expiration_check_date,
            (uint32_t*)p_collateral_expiration_status,
            (sgx_ql_qv_result_t*)p_quote_verification_result,
            (sgx_ql_qe_report_info_t*)p_qve_report_info,
            (uint32_t)supplemental_data_size,
            p_supplemental_data);

        oe_free(p_sgx_endorsements);

        // To align with current quote verification logic, only accept TCB
        // status
        // - UpToDate
        // - SW Hardening needed
        result = get_oe_result_t(error);
        if (result != OE_OK)
        {
            OE_RAISE_MSG(
                result,
                "SGX ECDSA QVL-based SGX quote verification error: "
                "_sgx_qv_verify_quote failed with quote3_error_t=%s\n",
                get_quote3_error_t_string(error));
        }

        OE_TRACE_INFO("verification status=%d", *p_quote_verification_result);
    }
    else
    {
        // SGX_DCAP_QVL env isn't set or QVL doesn't exist
        result = OE_PLATFORM_ERROR;
    }

done:
    return result;
}

oe_result_t oe_tdx_get_supplemental_data_size(
    const uint8_t* p_quote,
    uint32_t quote_size,
    uint32_t* p_version,
    uint32_t* p_data_size)
{
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;
    oe_result_t result = OE_UNEXPECTED;

    if (!p_quote || !quote_size || !p_version || !p_data_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!_load_tdx_dcap_qvl() || !_tee_get_supplemental_data_version_and_size)
        OE_RAISE(OE_PLATFORM_ERROR);

    error = _tee_get_supplemental_data_version_and_size(
        p_quote, quote_size, p_version, p_data_size);

    result = get_oe_result_t(error);

    if (result != OE_OK)
    {
        OE_RAISE_MSG(
            result,
            "Fail to get TDX quote supplemental data size "
            "quote3_error_t=%s\n",
            get_quote3_error_t_string(error));
    }

    OE_TRACE_INFO(
        "tdx supplemental data size=%u, major version=%u, minor version=%u",
        *p_data_size,
        ((supp_ver_t*)p_version)->major_version,
        ((supp_ver_t*)p_version)->minor_version);

done:
    return result;
}

/* Unserialize the flatten buffer that was serialized by
 * _serialize_tdx_quote_collateral */
static oe_result_t _unserialize_tdx_quote_collateral(
    const uint8_t* p_collateral,
    size_t collateral_size,
    uint8_t** collateral_unserialized)
{
    tdx_ql_qve_collateral_t* collateral_out = NULL;
    oe_result_t result = OE_FAILURE;
    uint8_t* cursor_end = NULL;
    uint8_t* cursor = NULL;

    /* Make a copy of the struct on the heap to avoid modify the const buffer.
     * The pointers inside the copied struct will point to the const memory so
     * that we don't over commit memory. */
    collateral_out = oe_malloc(collateral_size);
    if (!collateral_out)
        OE_RAISE(OE_OUT_OF_MEMORY);

    memcpy(collateral_out, p_collateral, sizeof(tdx_ql_qve_collateral_t));

    /* Support the following versions for now */
    if (collateral_out->version != SGX_QL_QVE_COLLATERAL_VERSION_3_0 &&
        collateral_out->version != SGX_QL_QVE_COLLATERAL_VERSION_3_1 &&
        collateral_out->version != SGX_QL_QVE_COLLATERAL_VERSION_4_0)
    {
        OE_RAISE_MSG(
            OE_INVALID_ENDORSEMENT,
            "Invalid collateral version %d",
            collateral_out->version);
    }

    cursor = (uint8_t*)p_collateral;
    cursor_end = (uint8_t*)p_collateral + collateral_size;

    cursor += sizeof(tdx_ql_qve_collateral_t);
    if (cursor >= cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    collateral_out->pck_crl_issuer_chain = (char*)cursor;
    cursor += collateral_out->pck_crl_issuer_chain_size;
    if (cursor >= cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    collateral_out->root_ca_crl = (char*)cursor;
    cursor += collateral_out->root_ca_crl_size;
    if (cursor >= cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    collateral_out->pck_crl = (char*)cursor;
    cursor += collateral_out->pck_crl_size;
    if (cursor >= cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    collateral_out->tcb_info_issuer_chain = (char*)cursor;
    cursor += collateral_out->tcb_info_issuer_chain_size;
    if (cursor >= cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    collateral_out->tcb_info = (char*)cursor;
    cursor += collateral_out->tcb_info_size;
    if (cursor >= cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    collateral_out->qe_identity_issuer_chain = (char*)cursor;
    cursor += collateral_out->qe_identity_issuer_chain_size;
    if (cursor >= cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    collateral_out->qe_identity = (char*)cursor;
    cursor += collateral_out->qe_identity_size;
    /* should reach the end of the buffer */
    if (cursor != cursor_end)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    *collateral_unserialized = (uint8_t*)collateral_out;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_tdx_verify_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const uint8_t* p_quote,
    uint32_t quote_size,
    const uint8_t* p_endorsements,
    uint32_t endorsements_size,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size)
{
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;
    tee_supp_data_descriptor_t supp_data = {0};
    uint8_t* endorsements_unserialized = NULL;
    oe_result_t result = OE_UNEXPECTED;

    // Input validation
    // Only support ECDSA-p256 now
    if (memcmp(
            format_id, &_tdx_ecdsa_p256_uuid, sizeof(_tdx_ecdsa_p256_uuid)) !=
        0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!p_collateral_expiration_status || !p_quote_verification_result ||
        !p_quote || quote_size > OE_MAX_UINT32 ||
        (!opt_params && opt_params_size > 0) ||
        (!p_endorsements && endorsements_size > 0) ||
        (!p_qve_report_info && qve_report_info_size > 0) ||
        (!p_supplemental_data && supplemental_data_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    if ((p_qve_report_info &&
         qve_report_info_size != sizeof(sgx_ql_qe_report_info_t)))
        OE_RAISE(OE_INVALID_PARAMETER);
    // End of input validation

    // Always use QvE/QVL for TDX verification
    if (!_load_tdx_dcap_qvl() || !_tee_verify_quote)
        OE_RAISE(OE_PLATFORM_ERROR);

    supp_data.p_data = p_supplemental_data;
    supp_data.data_size = supplemental_data_size;

    if (p_endorsements && endorsements_size)
    {
        OE_CHECK(_unserialize_tdx_quote_collateral(
            p_endorsements, endorsements_size, &endorsements_unserialized));
    }

    error = _tee_verify_quote(
        p_quote,
        (uint32_t)quote_size,
        (const tdx_ql_qve_collateral_t*)endorsements_unserialized,
        expiration_check_date,
        (uint32_t*)p_collateral_expiration_status,
        (sgx_ql_qv_result_t*)p_quote_verification_result,
        (sgx_ql_qe_report_info_t*)p_qve_report_info,
        (uint8_t*)&supp_data);

    // Only accept TCB status with UpToUpdate for now
    if (error != SGX_QL_SUCCESS)
    {
        /* Manually check the following two error codes so that
         * we do not map them to OE_OK for TDX verification */
        if (error == SGX_QL_TCB_SW_HARDENING_NEEDED)
            result = OE_TCB_LEVEL_INVALID;
        else if (error == SGX_QL_SGX_TCB_INFO_EXPIRED)
            result = OE_INVALID_ENDORSEMENT;
        else
            result = get_oe_result_t(error);

        OE_RAISE_MSG(
            result,
            "SGX ECDSA QvE/QVL-based TDX quote verification error "
            "quote3_error_t=%s\n",
            get_quote3_error_t_string(error));
    }

    OE_TRACE_INFO("verification status=%d", *p_quote_verification_result);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _serialize_tdx_quote_collateral(
    tdx_ql_qve_collateral_t* p_collateral,
    uint32_t collateral_size,
    uint8_t** pp_collateral)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* cursor_next = NULL;
    uint8_t* cursor_end = NULL;
    uint8_t* buffer = NULL;
    uint8_t* cursor = NULL;

    if (!p_collateral || !collateral_size || !pp_collateral)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Support the following versions for now */
    if (p_collateral->version != SGX_QL_QVE_COLLATERAL_VERSION_3_0 &&
        p_collateral->version != SGX_QL_QVE_COLLATERAL_VERSION_3_1 &&
        p_collateral->version != SGX_QL_QVE_COLLATERAL_VERSION_4_0)
    {
        OE_RAISE_MSG(
            OE_INVALID_ENDORSEMENT,
            "Invalid collateral version %d",
            p_collateral->version);
    }

    buffer = (uint8_t*)malloc(collateral_size);
    if (!buffer)
        OE_RAISE(OE_OUT_OF_MEMORY);

    cursor = buffer;
    cursor_end = buffer + collateral_size;

    cursor_next = cursor + sizeof(tdx_ql_qve_collateral_t);
    if (cursor_next >= cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(cursor, p_collateral, sizeof(tdx_ql_qve_collateral_t));
    cursor = cursor_next;

    cursor_next = cursor + p_collateral->pck_crl_issuer_chain_size;
    if (cursor_next >= cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(
        cursor,
        p_collateral->pck_crl_issuer_chain,
        p_collateral->pck_crl_issuer_chain_size);
    ((tdx_ql_qve_collateral_t*)buffer)->pck_crl_issuer_chain = (char*)cursor;
    cursor = cursor_next;

    cursor_next = cursor + p_collateral->root_ca_crl_size;
    if (cursor_next >= cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(cursor, p_collateral->root_ca_crl, p_collateral->root_ca_crl_size);
    ((tdx_ql_qve_collateral_t*)buffer)->root_ca_crl = (char*)cursor;
    cursor = cursor_next;

    cursor_next = cursor + p_collateral->pck_crl_size;
    if (cursor_next >= cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(cursor, p_collateral->pck_crl, p_collateral->pck_crl_size);
    ((tdx_ql_qve_collateral_t*)buffer)->pck_crl = (char*)cursor;
    cursor = cursor_next;

    cursor_next = cursor + p_collateral->tcb_info_issuer_chain_size;
    if (cursor_next >= cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(
        cursor,
        p_collateral->tcb_info_issuer_chain,
        p_collateral->tcb_info_issuer_chain_size);
    ((tdx_ql_qve_collateral_t*)buffer)->tcb_info_issuer_chain = (char*)cursor;
    cursor = cursor_next;

    cursor_next = cursor + p_collateral->tcb_info_size;
    if (cursor_next >= cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(cursor, p_collateral->tcb_info, p_collateral->tcb_info_size);
    ((tdx_ql_qve_collateral_t*)buffer)->tcb_info = (char*)cursor;
    cursor = cursor_next;

    cursor_next = cursor + p_collateral->qe_identity_issuer_chain_size;
    if (cursor_next >= cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(
        cursor,
        p_collateral->qe_identity_issuer_chain,
        p_collateral->qe_identity_issuer_chain_size);
    ((tdx_ql_qve_collateral_t*)buffer)->qe_identity_issuer_chain =
        (char*)cursor;
    cursor = cursor_next;

    cursor_next = cursor + p_collateral->qe_identity_size;
    /* should reach the end of the buffer at this point */
    if (cursor_next != cursor_end)
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    memcpy(cursor, p_collateral->qe_identity, p_collateral->qe_identity_size);
    ((tdx_ql_qve_collateral_t*)buffer)->qe_identity = (char*)cursor;

    *pp_collateral = buffer;

    result = OE_OK;

done:
    return result;
}

static oe_result_t _free_tdx_quote_verification_collateral(
    uint8_t* p_quote_collateral)
{
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;
    oe_result_t result = OE_FAILURE;

    if (!p_quote_collateral)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Always use QvE/QVL for TDX verification
    if (!_load_tdx_dcap_qvl())
        OE_RAISE(OE_PLATFORM_ERROR);

    error = _tee_qv_free_collateral(p_quote_collateral);

    if (error != SGX_QL_SUCCESS)
    {
        OE_RAISE_MSG(
            result,
            "Fail to free TDX quote collateral "
            "quote3_error_t=%s\n",
            get_quote3_error_t_string(error));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_tdx_quote_verification_collateral(
    const uint8_t* p_quote,
    uint32_t quote_size,
    uint8_t** pp_quote_collateral,
    uint32_t* p_collateral_size)
{
    quote3_error_t error = SGX_QL_ERROR_UNEXPECTED;
    oe_result_t result = OE_FAILURE;
    uint8_t* p_collateral = NULL;
    uint32_t collateral_size = 0;

    if (!p_quote || !quote_size || !pp_quote_collateral || !p_collateral_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Always use QvE/QVL for TDX verification
    if (!_load_tdx_dcap_qvl() || !_tee_qv_get_collateral)
        OE_RAISE(OE_PLATFORM_ERROR);

    // Fetch collateral information
    error = _tee_qv_get_collateral(
        p_quote, quote_size, &p_collateral, &collateral_size);

    if (error != SGX_QL_SUCCESS)
    {
        OE_RAISE_MSG(
            result,
            "Fail to get TDX quote collateral "
            "quote3_error_t=%s\n",
            get_quote3_error_t_string(error));
    }

    OE_TRACE_INFO("TDX quote verification collateral size=%u", collateral_size);

    OE_CHECK(_serialize_tdx_quote_collateral(
        (tdx_ql_qve_collateral_t*)p_collateral,
        collateral_size,
        pp_quote_collateral));

    *p_collateral_size = collateral_size;

    result = OE_OK;

done:
    _free_tdx_quote_verification_collateral(p_collateral);
    return result;
}

oe_result_t oe_free_tdx_quote_verification_collateral(
    uint8_t* p_quote_collateral)
{
    free(p_quote_collateral);

    return OE_OK;
}
