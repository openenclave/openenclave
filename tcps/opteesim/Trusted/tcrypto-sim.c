/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <windows.h>
#include <wincrypt.h>
#include <tee_api.h>
#include <assert.h>

void TEE_GenerateRandom(
    _Out_writes_bytes_(randomBufferLen) void* randomBuffer,
    _In_ size_t randomBufferLen)
{
    HCRYPTPROV hCryptProv = (HCRYPTPROV)NULL;

    if (!CryptAcquireContextW(&hCryptProv,
                              NULL,
                              NULL,
                              PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT))
    {
        assert(FALSE);
    }

    if (!CryptGenRandom(hCryptProv, randomBufferLen, randomBuffer))
    {
        assert(FALSE);
    }

    CryptReleaseContext(hCryptProv, 0);
}
