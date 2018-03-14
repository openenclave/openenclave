#include <mbedtls/sha256.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/sha.h>
#include <openenclave/types.h>

typedef struct _OE_SHA256ContextImpl
{
    mbedtls_sha256_context ctx;
} OE_SHA256ContextImpl;

OE_STATIC_ASSERT(sizeof(OE_SHA256ContextImpl) <= sizeof(OE_SHA256Context));

void OE_SHA256Init(OE_SHA256Context* context)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (impl)
    {
        mbedtls_sha256_init(&impl->ctx);
        mbedtls_sha256_starts(&impl->ctx, 0);
    }
}

void OE_SHA256Update(OE_SHA256Context* context, const void* data, size_t size)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (impl)
        mbedtls_sha256_update(&impl->ctx, data, size);
}

void OE_SHA256UpdateZeros(OE_SHA256Context* context, size_t size)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;
    unsigned char zeros[128];

    if (!impl)
        return;

    OE_Memset(zeros, 0, sizeof(zeros));

    while (size)
    {
        if (size < sizeof(zeros))
        {
            mbedtls_sha256_update(&impl->ctx, zeros, size);
            size -= size;
        }
        else
        {
            mbedtls_sha256_update(&impl->ctx, zeros, sizeof(zeros));
            size -= sizeof(zeros);
        }
    }
}

void OE_SHA256Final(OE_SHA256Context* context, OE_SHA256* sha256)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (impl)
        mbedtls_sha256_finish(&impl->ctx, sha256->buf);
}

/* Convert a nibble to an ASCII character: Example 0xF => 'F' */
OE_INLINE char _NibbleToHexChar(uint8_t x)
{
    return (x < 10) ? ('0' + x) : ('A' + (x - 10));
}

/* Convert a byte to an ASCII hex string. Example: 0x3F => "3F" */
static void _ByteToHexString(uint8_t byte, char buf[3])
{
    /* Convert high nibble to character */
    buf[0] = _NibbleToHexChar(byte >> 4);

    /* Convert low nibble to character */
    buf[1] = _NibbleToHexChar(byte & 0x0F);

    /* Zero-terminate the string */
    buf[2] = '\0';
}

void OE_SHA256ToStr(const OE_SHA256* sha256, OE_SHA256Str* str)
{
    if (sha256 && str)
    {
        size_t i;

        for (i = 0; i < OE_SHA256_SIZE; i++)
            _ByteToHexString(sha256->buf[i], &str->buf[i * 2]);
    }
}

OE_SHA256Str OE_SHA256StrOf(const OE_SHA256* sha256)
{
    static OE_SHA256Str empty;
    static OE_SHA256Str result;

    if (!sha256)
        return empty;

    OE_SHA256ToStr(sha256, &result);
    return result;
}

OE_SHA256Str OE_SHA256StrOfContext(const OE_SHA256Context* context)
{
    static OE_SHA256Str empty;
    static OE_SHA256Context copy;
    OE_SHA256 sha256;

    if (!context)
        return empty;

    copy = *context;

    OE_SHA256Final(&copy, &sha256);
    return OE_SHA256StrOf(&sha256);
}
