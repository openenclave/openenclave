#include <string.h>
#include <stdio.h>

#if defined(__linux__)
# include <openssl/sha.h>
#elif defined(_WIN32)
# include <Windows.h>
# include <bcrypt.h>
#endif

#ifdef OE_BUILD_ENCLAVE
# include <openenclave/enclave.h>
#else
# include <openenclave/host.h>
#endif

typedef struct _OE_SHA256ContextImpl
{
#if defined(__linux__)
    SHA256_CTX ctx;
#elif defined(_WIN32)
    BCRYPT_HASH_HANDLE handle;
#endif
}
OE_SHA256ContextImpl;

OE_STATIC_ASSERT(sizeof(OE_SHA256ContextImpl) <= sizeof(OE_SHA256Context));

void OE_SHA256Init(
    OE_SHA256Context* context)
{
    if (!context)
        return;

    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

#if defined(__linux__)
    SHA256_Init(&impl->ctx);
#elif defined(_WIN32)
    BCryptCreateHash(
        BCRYPT_SHA256_ALG_HANDLE, 
        &impl->handle, 
        NULL, 
        0, 
        NULL, 
        0, 
        0);
#endif
}

void OE_SHA256Update(
    OE_SHA256Context* context,
    const void* data,
    size_t size)
{
    if (!context)
        return;

    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

#if defined(__linux__)
    SHA256_Update(&impl->ctx, data, size);
#elif defined(_WIN32)
    BCryptHashData(impl->handle, (void*)data, (ULONG)size, 0);
#endif
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
#if defined(__linux__)
            SHA256_Update(&impl->ctx, zeros, size);
#elif defined(_WIN32)
            BCryptHashData(impl->handle, zeros, (ULONG)size, 0);
#endif
            size -= size;
        }
        else
        {
#if defined(__linux__)
            SHA256_Update(&impl->ctx, zeros, sizeof(zeros));
#elif defined(_WIN32)
            BCryptHashData(impl->handle, zeros, sizeof(zeros), 0);
#endif
            size -= sizeof(zeros);
        }
    }
}

void OE_SHA256Final(
    OE_SHA256Context* context,
    OE_SHA256* sha256)
{
    if (!context)
        return;

    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

#if defined(__linux__)
    SHA256_Final(sha256->buf, &impl->ctx);
#elif defined(_WIN32)
    BCryptFinishHash(impl->handle, sha256->buf, sizeof(OE_SHA256), 0);
#endif
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

