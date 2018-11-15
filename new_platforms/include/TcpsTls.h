/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
/*++

Module Name:

    TcpsTls.h

Abstract:

    Definition of TLS connection, wrapping .

--*/
#pragma once

#include "tcps.h"
#include "ICryptUtil.h"


#ifdef __cplusplus
extern "C" {
#endif

#ifndef TCPS_BASIC_TYPES_ONLY
#include <stdint.h>

// TODO: So we need to abstract the connection/transport under TLS.
// this is the skeleton to achieve that. Starting simply and building out to something more generic
typedef int(*EstablishConnnection)(const char* hostName,
    uint16_t serviceName,
    uint32_t timeout,
    void** ctx);

typedef int(*SendPayload)(const uint8_t* buf,
    uint32_t sz,
    uint32_t timeout,
    uint32_t *sent,
    void* ctx);

typedef int(*ReceivePayload)(uint8_t* buf,
    uint32_t sz,
    uint32_t timeout,
    uint32_t *recvd,
    void* ctx);

typedef void(*CloseConnection)(void** ctx);

typedef struct _TRANSPORT_CALLBACKS {
    EstablishConnnection TcpsConnect;
    SendPayload TcpsSend;
    ReceivePayload TcpsReceive;
    CloseConnection TcpsDisconnect;
} TRANSPORT_CALLBACKS, *PTRANSPORT_CALLBACKS;

typedef struct _TCPS_CONNECTION_CTX {
    TRANSPORT_CALLBACKS TptCB;

    // Context pointer used in the transport callbacks to track a connection.
    // This pointer is expected to be allocated by TcpsConnect and
    // deallocated by TcpsDisconnect
    void* CallbackContext;
} TCPS_CONNECTION_CTX, *PTCPS_CONNECTION_CTX;

typedef enum _TcpsEncoding {
    TcpsDerEncoded = 0,
    TcpsPemEncoded,
    TcpsEncodingMax
} TcpsEncoding;

typedef struct _TCPS_BUFFER {
    uint8_t *Buffer;
    uint32_t BufferSize;
} TCPS_BUFFER, *PTCPS_BUFFER;

typedef struct _TCPS_CERTSTORE {
    uint32_t CertBagLen;
    const char* CertBag; // This will be 0-terminated
} TCPS_CERTSTORE, *PTCPS_CERTSTORE;

#include "ICryptUtil.h"
typedef struct _TCPS_TA_ID_INFO {
    RIOT_ECC_PUBLIC FwDevicePubKey;
    RIOT_ECC_PUBLIC CompoundPubKey;
    RIOT_ECC_PRIVATE CompoundPrivKey;
    TCPS_CERTSTORE IssuedCert;
} TCPS_TA_ID_INFO, *PTCPS_TA_ID_INFO;
#endif // !TCPS_BASIC_TYPES_ONLY

typedef void *TCPS_TLS_HANDLE;

typedef int( *VerifyCertCallback )(int, void*);

oe_result_t
TcpsTlsCreateServerContext(
    const TCPS_TA_ID_INFO* const TAIdentityInfo,
    PTCPS_CONNECTION_CTX Connection,
    TCPS_TLS_HANDLE *TlsHandle
);

oe_result_t
TcpsTlsCreateContext(
    const TCPS_TA_ID_INFO *TAIdentityInfo,
    PTCPS_CONNECTION_CTX Connection,
    TCPS_TLS_HANDLE *TlsHandle
);

void
TcpsTlsCloseContext(
    TCPS_TLS_HANDLE Ctx
);

oe_result_t
TcpsTlsAuthorizeAuthority(
    TCPS_TLS_HANDLE Handle,
    TcpsEncoding AuthorityEncoding,
    const uint8_t* const Authority,
    uint32_t AuthoritySize
);

oe_result_t
TcpsTlsAccept(
    TCPS_TLS_HANDLE Handle,
    VerifyCertCallback ValidatePeer,
    uint16_t LocalPort,
    uint32_t Timeoutms
);

oe_result_t
TcpsTlsConnect(
    TCPS_TLS_HANDLE Handle,
    const char *ServerUri,
    uint16_t ServerPort,
    uint32_t Timeoutms
);

oe_result_t
TcpsTlsConnectClient(
    const TCPS_TA_ID_INFO* const IdentityData,
    PTCPS_CONNECTION_CTX TcpsCntCtx,
    const uint8_t* const AuthorityBuffer,
    const uint32_t AuthorityBufferSize,
    const char* const ServerUri,
    const uint16_t ServerPort,
    const uint32_t TimeoutMs,
    TCPS_TLS_HANDLE* const TlsHandle
);

oe_result_t
TcpsTlsAcceptClient(
    const TCPS_TA_ID_INFO* const IdentityData,
    PTCPS_CONNECTION_CTX TcpsCntCtx,
    const uint8_t* const AuthorityBuffer, // TODO support more than 1
    const uint32_t AuthorityBufferSize,
    const uint16_t LocalPort,
    const VerifyCertCallback VerifyCb,
    const uint32_t TimeoutMs,
    TCPS_TLS_HANDLE* const TlsHandle
);

void
TcpsTlsDisconnect(
    TCPS_TLS_HANDLE Handle
);

void
TcpsTlsCloseHandle(
    TCPS_TLS_HANDLE TlsHandle
);

oe_result_t
TcpsTlsWrite(
    TCPS_TLS_HANDLE Handle,
    const uint8_t* Data,
    uint32_t DataSize,
    uint32_t Timeoutms
);

oe_result_t
TcpsTlsRead(
    TCPS_TLS_HANDLE Handle,
    uint8_t** Data,
    uint32_t* DataSize,
    uint32_t Timeoutms
);

oe_result_t
TcpsTlsGetPublicKeyFromLeafPem(
    const char* PemCertChain,
    RIOT_ECC_PUBLIC* const PublicKey
);

oe_result_t
TcpsTlsGetPublicKeyFromPeer(
    TCPS_TLS_HANDLE TlsHandle,
    RIOT_ECC_PUBLIC* const PublicKey
);

// TcpsTlsGetPeerCertChain is supported 
// when wolfssl is configured to save the 
// peer certificate for this session
#ifdef SESSION_CERTS
oe_result_t
TcpsTlsGetPeerCertChain(
    TCPS_TLS_HANDLE TlsHandle,
    uint8_t *PemPeerCertChainBuf,
    uint32_t PemPeerCertChainBufSize,
    uint32_t *RequiredSize
);
#endif //SESSION_CERTS

#ifdef __cplusplus
}
#endif
