#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openenclave.h>

typedef struct _OE_SHA256ContextImpl
{
    SHA256_CTX ctx;
}
OE_SHA256ContextImpl;

OE_STATIC_ASSERT(sizeof(OE_SHA256ContextImpl) <= sizeof(OE_SHA256Context));

void OE_SHA256Init(
    OE_SHA256Context* context)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (impl)
        SHA256_Init(&impl->ctx);
}

void OE_SHA256Update(
    OE_SHA256Context* context,
    const void* data,
    size_t size)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (impl)
        SHA256_Update(&impl->ctx, data, size);
}

void OE_SHA256UpdateZeros(
    OE_SHA256Context* context,
    size_t size)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;
    char zeros[128];

    if (!impl)
        return;

    memset(zeros, 0, sizeof(zeros));

    while (size)
    {
        if (size < sizeof(zeros))
        {
            SHA256_Update(&impl->ctx, zeros, size);
            size -= size;
        }
        else
        {
            SHA256_Update(&impl->ctx, zeros, sizeof(zeros));
            size -= sizeof(zeros);
        }
    }
}

void OE_SHA256Final(
    OE_SHA256Context* context,
    OE_SHA256* sha256)
{
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (impl)
        SHA256_Final(sha256->buf, &impl->ctx);
}

void OE_SHA256ToStr(
    const OE_SHA256* sha256,
    OE_SHA256Str* str)
{
    if (sha256 && str)
    {
        size_t i;

        for (i = 0; i < OE_SHA256_SIZE; i++)
            snprintf(&str->buf[i*2], 3, "%02x", sha256->buf[i]);
    }
}

OE_SHA256Str OE_SHA256StrOf(
    const OE_SHA256* sha256)
{
    static OE_SHA256Str empty;
    static OE_SHA256Str result;

    if (!sha256)
        return empty;

    OE_SHA256ToStr(sha256, &result);
    return result;
}

OE_SHA256Str OE_SHA256StrOfContext(
    const OE_SHA256Context* context)
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

