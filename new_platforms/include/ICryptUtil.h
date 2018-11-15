/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
/*++

Module Name:

    ICryptUtil.h

Abstract:

    Wrapper functions for encryption routines

--*/
#pragma once

#include <stdlib.h>
#include <RiotTarget.h>
#include <RiotStatus.h>
#include <RiotSha256.h>
#include <RiotHmac.h>
#include <RiotKdf.h>
#include <RiotEcc.h>
#include <RiotCrypt.h>

#include "tcps.h"

#define TCPS_ECC_PUBLIC_SERIALIZED (1 + 2 * RIOT_ECC_COORD_BYTES)

typedef RIOT_SHA256_CONTEXT TCPS_SHA256_CONTEXT;
typedef uint8_t TCPS_SHA256_DIGEST[SHA256_DIGEST_LENGTH];
typedef uint8_t TCPS_IDENTITY_PUBLIC_SERIALIZED[TCPS_ECC_PUBLIC_SERIALIZED];

typedef ecc_privatekey TCPS_IDENTITY_PRIVATE;
typedef ecc_publickey TCPS_IDENTITY_PUBLIC;
typedef ecc_signature TCPS_IDENTITY_SIGNATURE;

#ifdef __cplusplus
extern "C" {
#endif

oe_result_t
TcpsAESDecrypt(
    uint8_t *aes_key,
    uint8_t *ciphertext,
    uint32_t ciphertext_length,
    uint8_t *initialization_vector,
    uint8_t **cleartext,
    uint32_t *cleartext_length
);


oe_result_t
TcpsAESEncryptWithIv(
    uint8_t *aes_key,
    const uint8_t *cleartext,
    uint32_t cleartext_length,
    uint8_t *initialization_vector,
    uint8_t **ciphertext,
    uint32_t *ciphertext_length
);

inline void
TcpsSha256Init(
    TCPS_SHA256_CONTEXT *Context )
{
    RIOT_SHA256_Init(Context);
}

inline void
TcpsSha256Update(
    TCPS_SHA256_CONTEXT *Context,
    const uint8_t *Data,
    uint32_t Len )
{
    RIOT_SHA256_Update( Context, Data, Len );
}

inline void
TcpsSha256Final( 
    TCPS_SHA256_CONTEXT *Context,
    uint8_t *Digest)
{
    RIOT_SHA256_Final(Context, Digest);
}

inline void
TcpsSHA256Block(
    const uint8_t *buf, uint32_t bufSize, uint8_t *digest
)
{
    RIOT_SHA256_Block( buf, bufSize, digest );
}

#ifdef __cplusplus
}
#endif
