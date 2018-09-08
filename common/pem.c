#include <openenclave/internal/base64.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/raise.h>
#include <string.h>

#define STRING_INFO_INITIALIZER(STR) \
    {                                \
        STR, sizeof(STR) - 1         \
    }

/* Represents a string and its length. */
typedef struct _string_info
{
    const char* str;
    size_t len;
} string_info_t;

static const string_info_t _headers[] = {
    STRING_INFO_INITIALIZER(OE_PEM_BEGIN_CERTIFICATE "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_BEGIN_PUBLIC_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_BEGIN_PRIVATE_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_BEGIN_RSA_PRIVATE_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_BEGIN_EC_PRIVATE_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_BEGIN_X509_CRL "\n"),
};

static const string_info_t _footers[] = {
    STRING_INFO_INITIALIZER(OE_PEM_END_CERTIFICATE "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_END_PUBLIC_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_END_PRIVATE_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_END_RSA_PRIVATE_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_END_EC_PRIVATE_KEY "\n"),
    STRING_INFO_INITIALIZER(OE_PEM_END_X509_CRL "\n"),
};

oe_result_t oe_der_to_pem(
    const uint8_t* der,
    size_t der_size,
    oe_pem_type_t type,
    uint8_t* pem,
    size_t* pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const char* begin;
    size_t begin_len;
    const char* end;
    size_t end_len;
    size_t total_size;

    if (!der || !der_size || !pem_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If the pem buffer is null, then the size must be zero. */
    if (!pem && *pem_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Select the PEM headers and footers. */
    begin = _headers[type].str;
    begin_len = _headers[type].len;
    end = _footers[type].str;
    end_len = _footers[type].len;

    /* Calculate the total size of the PEM buffer. */
    {
        size_t size = 0;

        if (oe_base64_encode(der, der_size, true, NULL, &size) !=
            OE_BUFFER_TOO_SMALL)
        {
            OE_RAISE(OE_FAILURE);
        }

        /* Include the zero-terminator in the size calculation. */
        total_size = begin_len + size + end_len + sizeof(uint8_t);
    }

    /* Fail if the caller's PEM buffer is too small. */
    if (total_size > *pem_size)
    {
        *pem_size = total_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Convert the DER buffer to PEM format. */
    {
        size_t off = 0;
        size_t size;

        /* Format the PEM header. */
        memcpy(&pem[off], begin, begin_len);
        off += begin_len;

        /* Convert the DER buffer to base-64 encoding */
        OE_CHECK(oe_base64_encode(der, der_size, true, &pem[off], &size));
        off += size;

        /* Format the PEM footer. */
        memcpy(&pem[off], end, end_len);
        off += end_len;

        pem[off++] = '\0';

        *pem_size = off;
    }

    result = OE_OK;

done:
    return result;
}
