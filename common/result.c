// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/result.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/result.h>

OE_STATIC_ASSERT(sizeof(oe_result_t) == sizeof(unsigned int));

// OE abort status depends on the order of these enums to transfer status
// correctly.
OE_STATIC_ASSERT(OE_ENCLAVE_ABORTING > OE_OK);
OE_STATIC_ASSERT(OE_ENCLAVE_ABORTED > OE_ENCLAVE_ABORTING);

const char* oe_result_str(oe_result_t result)
{
    switch (result)
    {
        case OE_OK:
            return "OE_OK";
        case OE_FAILURE:
            return "OE_FAILURE";
        case OE_BUFFER_TOO_SMALL:
            return "OE_BUFFER_TOO_SMALL";
        case OE_INVALID_PARAMETER:
            return "OE_INVALID_PARAMETER";
        case OE_REENTRANT_ECALL:
            return "OE_REENTRANT_ECALL";
        case OE_OUT_OF_MEMORY:
            return "OE_OUT_OF_MEMORY";
        case OE_OUT_OF_THREADS:
            return "OE_OUT_OF_THREADS";
        case OE_UNEXPECTED:
            return "OE_UNEXPECTED";
        case OE_VERIFY_FAILED:
            return "OE_VERIFY_FAILED";
        case OE_NOT_FOUND:
            return "OE_NOT_FOUND";
        case OE_INTEGER_OVERFLOW:
            return "OE_INTEGER_OVERFLOW";
        case OE_PUBLIC_KEY_NOT_FOUND:
            return "OE_PUBLIC_KEY_NOT_FOUND";
        case OE_OUT_OF_BOUNDS:
            return "OE_OUT_OF_BOUNDS";
        case OE_OVERLAPPED_COPY:
            return "OE_OVERLAPPED_COPY";
        case OE_CONSTRAINT_FAILED:
            return "OE_CONSTRAINT_FAILED";
        case OE_IOCTL_FAILED:
            return "OE_IOCTL_FAILED";
        case OE_UNSUPPORTED:
            return "OE_UNSUPPORTED";
        case OE_READ_FAILED:
            return "OE_READ_FAILED";
        case OE_SERVICE_UNAVAILABLE:
            return "OE_SERVICE_UNAVAILABLE";
        case OE_ENCLAVE_ABORTING:
            return "OE_ENCLAVE_ABORTING";
        case OE_ENCLAVE_ABORTED:
            return "OE_ENCLAVE_ABORTED";
        case OE_PLATFORM_ERROR:
            return "OE_PLATFORM_ERROR";
        case OE_INVALID_CPUSVN:
            return "OE_INVALID_CPUSVN";
        case OE_INVALID_ISVSVN:
            return "OE_INVALID_ISVSVN";
        case OE_INVALID_KEYNAME:
            return "OE_INVALID_KEYNAME";
        case OE_DEBUG_DOWNGRADE:
            return "OE_DEBUG_DOWNGRADE";
        case OE_REPORT_PARSE_ERROR:
            return "OE_REPORT_PARSE_ERROR";
        case OE_MISSING_CERTIFICATE_CHAIN:
            return "OE_MISSING_CERTIFICATE_CHAIN";
        case OE_BUSY:
            return "OE_BUSY";
        case OE_NOT_OWNER:
            return "OE_NOT_OWNER";
        case OE_INVALID_SGX_CERTIFICATE_EXTENSIONS:
            return "OE_INVALID_SGX_CERTIFICATE_EXTENSIONS";
        case OE_MEMORY_LEAK:
            return "OE_MEMORY_LEAK";
        case OE_BAD_ALIGNMENT:
            return "OE_BAD_ALIGNMENT";
        case OE_JSON_INFO_PARSE_ERROR:
            return "OE_JSON_INFO_PARSE_ERROR";
        case OE_TCB_LEVEL_INVALID:
            return "OE_TCB_LEVEL_INVALID";
        case OE_QUOTE_PROVIDER_LOAD_ERROR:
            return "OE_QUOTE_PROVIDER_LOAD_ERROR";
        case OE_QUOTE_PROVIDER_CALL_ERROR:
            return "OE_QUOTE_PROVIDER_CALL_ERROR";
        case OE_INVALID_REVOCATION_INFO:
            return "OE_INVALID_REVOCATION_INFO";
        case OE_INVALID_UTC_DATE_TIME:
            return "OE_INVALID_UTC_DATE_TIME";
        case OE_INVALID_QE_IDENTITY_INFO:
            return "OE_INVALID_QE_IDENTITY_INFO";
        case OE_INVALID_ENDORSEMENT:
            return "OE_INVALID_ENDORSEMENT";
        case OE_UNSUPPORTED_ENCLAVE_IMAGE:
            return "OE_UNSUPPORTED_ENCLAVE_IMAGE";
        case OE_VERIFY_CRL_EXPIRED:
            return "OE_VERIFY_CRL_EXPIRED";
        case OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD:
            return "OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD";
        case OE_VERIFY_CRL_MISSING:
            return "OE_VERIFY_CRL_MISSING";
        case OE_VERIFY_REVOKED:
            return "OE_VERIFY_REVOKED";
        case OE_CRYPTO_ERROR:
            return "OE_CRYPTO_ERROR";
        case OE_INCORRECT_REPORT_SIZE:
            return "OE_INCORRECT_REPORT_SIZE";
        case OE_QUOTE_VERIFICATION_ERROR:
            return "OE_QUOTE_VERIFICATION_ERROR";
        case OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED:
            return "OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED";
        case OE_QUOTE_ENCLAVE_IDENTITY_UNIQUEID_MISMATCH:
            return "OE_QUOTE_ENCLAVE_IDENTITY_UNIQUEID_MISMATCH";
        case QE_QUOTE_ENCLAVE_IDENTITY_PRODUCTID_MISMATCH:
            return "QE_QUOTE_ENCLAVE_IDENTITY_PRODUCTID_MISMATCH";
        case OE_VERIFY_FAILED_AES_CMAC_MISMATCH:
            return "OE_VERIFY_FAILED_AES_CMAC_MISMATCH";
        case OE_CONTEXT_SWITCHLESS_OCALL_MISSED:
            return "OE_CONTEXT_SWITCHLESS_OCALL_MISSED";
        case OE_THREAD_CREATE_ERROR:
            return "OE_THREAD_CREATE_ERROR";
        case OE_THREAD_JOIN_ERROR:
            return "OE_THREAD_JOIN_ERROR";
        case OE_ALREADY_EXISTS:
            return "OE_ALREADY_EXISTS";
        case OE_ALREADY_INITIALIZED:
            return "OE_ALREADY_INITIALIZED";
        case OE_QUOTE_HASH_MISMATCH:
            return "OE_QUOTE_HASH_MISMATCH";
        case __OE_RESULT_MAX:
            break;
    }

    return "UNKNOWN";
}

bool oe_is_valid_result(uint32_t result)
{
    switch ((oe_result_t)result)
    {
        case OE_OK:
        case OE_FAILURE:
        case OE_BUFFER_TOO_SMALL:
        case OE_INVALID_PARAMETER:
        case OE_REENTRANT_ECALL:
        case OE_OUT_OF_MEMORY:
        case OE_OUT_OF_THREADS:
        case OE_UNEXPECTED:
        case OE_VERIFY_FAILED:
        case OE_NOT_FOUND:
        case OE_INTEGER_OVERFLOW:
        case OE_PUBLIC_KEY_NOT_FOUND:
        case OE_OUT_OF_BOUNDS:
        case OE_OVERLAPPED_COPY:
        case OE_CONSTRAINT_FAILED:
        case OE_IOCTL_FAILED:
        case OE_UNSUPPORTED:
        case OE_READ_FAILED:
        case OE_SERVICE_UNAVAILABLE:
        case OE_ENCLAVE_ABORTING:
        case OE_ENCLAVE_ABORTED:
        case OE_PLATFORM_ERROR:
        case OE_INVALID_CPUSVN:
        case OE_INVALID_ISVSVN:
        case OE_INVALID_KEYNAME:
        case OE_DEBUG_DOWNGRADE:
        case OE_REPORT_PARSE_ERROR:
        case OE_MISSING_CERTIFICATE_CHAIN:
        case OE_BUSY:
        case OE_NOT_OWNER:
        case OE_INVALID_SGX_CERTIFICATE_EXTENSIONS:
        case OE_MEMORY_LEAK:
        case OE_BAD_ALIGNMENT:
        case OE_JSON_INFO_PARSE_ERROR:
        case OE_TCB_LEVEL_INVALID:
        case OE_QUOTE_PROVIDER_LOAD_ERROR:
        case OE_QUOTE_PROVIDER_CALL_ERROR:
        case OE_INVALID_REVOCATION_INFO:
        case OE_INVALID_UTC_DATE_TIME:
        case OE_INVALID_QE_IDENTITY_INFO:
        case OE_INVALID_ENDORSEMENT:
        case OE_UNSUPPORTED_ENCLAVE_IMAGE:
        case OE_VERIFY_CRL_EXPIRED:
        case OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD:
        case OE_VERIFY_CRL_MISSING:
        case OE_VERIFY_REVOKED:
        case OE_CRYPTO_ERROR:
        case OE_INCORRECT_REPORT_SIZE:
        case OE_QUOTE_VERIFICATION_ERROR:
        case OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED:
        case OE_QUOTE_ENCLAVE_IDENTITY_UNIQUEID_MISMATCH:
        case QE_QUOTE_ENCLAVE_IDENTITY_PRODUCTID_MISMATCH:
        case OE_VERIFY_FAILED_AES_CMAC_MISMATCH:
        case OE_CONTEXT_SWITCHLESS_OCALL_MISSED:
        case OE_THREAD_CREATE_ERROR:
        case OE_THREAD_JOIN_ERROR:
        case OE_ALREADY_EXISTS:
        case OE_ALREADY_INITIALIZED:
        case OE_QUOTE_HASH_MISMATCH:
        {
            return true;
        }
        case __OE_RESULT_MAX:
        {
            return false;
        }
            /* Please do not add a default case! */
    }

    return false;
}
