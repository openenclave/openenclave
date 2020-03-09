// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum _oe_log_level
{
    OE_LOG_LEVEL_NONE = 0,
    OE_LOG_LEVEL_FATAL,
    OE_LOG_LEVEL_ERROR,
    OE_LOG_LEVEL_WARNING,
    OE_LOG_LEVEL_INFO,
    OE_LOG_LEVEL_VERBOSE,
    OE_LOG_LEVEL_MAX
} oe_log_level_t;

oe_result_t oe_log(oe_log_level_t level, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "LOG: ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    return OE_OK;
}

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
        case __OE_RESULT_MAX:
            break;
    }

    return "UNKNOWN";
}

void* oe_malloc(size_t size)
{
    return malloc(size);
}

void* oe_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void oe_free(void* p)
{
    free(p);
}

oe_result_t oe_memset_s(void* dst, size_t dst_size, int value, size_t num_bytes)
{
    assert(dst && dst_size < num_bytes);
    memset(dst, value, num_bytes);
    return OE_OK;
}

oe_result_t oe_memcpy_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes)
{
    assert(dst && src && dst_size < num_bytes);
    memcpy(dst, src, num_bytes);
    return OE_OK;
}

int oe_strlen(const char* s)
{
    return strlen(s);
}

typedef struct _sgx_key_request sgx_key_request_t;
typedef struct _sgx_key sgx_key_t;

oe_result_t oe_get_key(
    const sgx_key_request_t* sgx_key_request,
    sgx_key_t* sgx_key)
{
    (void)sgx_key_request;
    (void)sgx_key;

    return OE_FAILURE;
}

oe_log_level_t oe_get_current_logging_level(void)
{
    return OE_LOG_LEVEL_INFO;
}

void oe_hex_dump(const void* data, size_t size)
{
    const uint8_t* p = (const uint8_t*)data;

    for (size_t i = 0; i < size; i++)
    {
        printf("%02x ", p[i]);
    }

    printf("\n");
}

typedef struct _oe_entropy_kind oe_entropy_kind_t;

oe_result_t oe_get_entropy(void* output, size_t len, oe_entropy_kind_t* kind)
{
    unsigned char* p = (unsigned char*)output;
    size_t bytes_left = len;

    if (output)
        memset(output, 0, len);

    if (!output || !kind)
        return OE_INVALID_PARAMETER;

    while (bytes_left > 0)
    {
        extern uint64_t oe_rdrand(void);
        uint64_t random = oe_rdrand();
        size_t copy_size =
            (sizeof(random) > bytes_left) ? bytes_left : sizeof(random);
        memcpy(p, &random, copy_size);
        p += copy_size;
        bytes_left -= copy_size;
    }

    return OE_OK;
}

typedef volatile uint32_t spinlock_t;

/* Set the spinlock value to 1 and return the old value */
static unsigned int _spin_set_locked(spinlock_t* spinlock)
{
    unsigned int value = 1;

    asm volatile("lock xchg %0, %1;"
                 : "=r"(value)     /* %0 */
                 : "m"(*spinlock), /* %1 */
                   "0"(value)      /* also %2 */
                 : "memory");

    return value;
}

static oe_result_t _spin_lock(spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    while (_spin_set_locked((volatile unsigned int*)spinlock) != 0)
    {
        /* Spin while waiting for spinlock to be released (become 1) */
        while (*spinlock)
        {
            /* Yield to CPU */
            asm volatile("pause");
        }
    }

    return OE_OK;
}

static oe_result_t _spin_unlock(spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    asm volatile("movl %0, %1;"
                 :
                 : "r"(0), "m"(*spinlock) /* %1 */
                 : "memory");

    return OE_OK;
}

static spinlock_t _lock;
typedef uint32_t oe_once_t;

oe_result_t oe_once(oe_once_t* once, void (*func)(void))
{
    if (!once)
        return OE_INVALID_PARAMETER;

    _spin_lock(&_lock);

    if (*once == 0)
    {
        func();
        *once = 1;
    }

    _spin_unlock(&_lock);

    return OE_OK;
}
