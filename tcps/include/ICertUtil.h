/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
/*++

Module Name:

    ICertUtil.h

Abstract:

    Wrapper functions for certificate manipulation.
    TCPS relies on external stacks for certificate manipulation. 
    This wrapper implementation is intended to allow these stacks
    to be replaced.

--*/
#pragma once

// This lib uses wolfssl to parse certificates.
// It is important to always to include the same user_setting.h
// that any wolf code linked with this binary was compiled with.
#include "user_settings.h"
#include "TcpsTls.h"

#include <stdlib.h>

// wolf is used for DER parsing

// RIoT is used for x509 creation and DER encoding
#include <RiotTarget.h>
#include <RiotStatus.h>
#include <RiotSha256.h>
#include <RiotHmac.h>
#include <RiotKdf.h>
#include <RiotEcc.h>
#include <RiotDerEnc.h>
#include <RiotX509Bldr.h>
#include <RiotCrypt.h>

#define PEM_CERT_BEGIN      "-----BEGIN CERTIFICATE-----"
#define PEM_CERT_END        "-----END CERTIFICATE-----"
#define PEM_ECC_BEGIN       "-----BEGIN EC PRIVATE KEY-----"

#ifdef __cplusplus
extern "C" {
#endif

#define DER_CERT_BUFF_INFO  TCPS_BUFFER

typedef struct _TCPS_DER_CERT_CHAIN {
    DER_CERT_BUFF_INFO *CertArray;
    uint32_t CertCount;
} TCPS_DER_CERT_CHAIN, *PTCPS_DER_CERT_CHAIN;

void
TcpsBufferToHexString(
    const uint8_t* const Buffer,
    const uint32_t BufferLength,
    char* const String
);

Tcps_StatusCode
TcpsPemToDer(
    char *PemCert,
    uint8_t *DerBuf,
    uint32_t DerBufSize,
    uint32_t *SizeNeeded
);

Tcps_StatusCode
TcpsExtractOIDExtension(
    uint8_t *DerBuf,
    uint32_t DerBufSize,
    const uint8_t *EncodedOid,
    uint32_t EncodedOidSize,
    uint8_t **OidData,
    uint32_t *OidDataSize
);

Tcps_StatusCode
TcpsLoadCertChain(
    const char *PemCertChain,
    PTCPS_DER_CERT_CHAIN DerCertArray
);

void
TcpsFreeCertChain(
    PTCPS_DER_CERT_CHAIN DerCertArray
);

Tcps_StatusCode
TcpsGetDeviceIdStrFromPem(
    const char* const CertBuffer,
    char* const DeviceIDStr,
    const uint32_t DeviceIDStrSize
);

Tcps_StatusCode
TcpsGetDeviceIdStr(
    const char* const PemCertChain,
    char* const DeviceIDStr,
    const uint32_t DeviceIDStrSize,
    uint32_t* const RequiredSize
);

Tcps_StatusCode
TcpsGetDeviceIdStrFromPublic(
    const RIOT_ECC_PUBLIC* const PublicKey,
    char* const DeviceIDStr,
    const uint32_t DeviceIDStrSize
);

Tcps_StatusCode
TcpsGetDeviceIdBinary(
    const char* const PemCertChain,
    uint8_t* const DeviceID,
    const uint32_t DeviceIDSize,
    uint32_t* const RequiredSize
);

Tcps_StatusCode
TcpsGetDeviceIdBinaryFromDerCertChain(
    const TCPS_DER_CERT_CHAIN* const DerCertChain,
    uint8_t* const DeviceID,
    const uint32_t DeviceIDSize,
    uint32_t* const RequiredSize
);

Tcps_StatusCode
TcpsGetDeviceIdBinaryFromPubKeyBuffer(
    const uint8_t* const PubKeyBuffer,
    const uint32_t PubKeyBufferSize,
    uint8_t* const DeviceIDBuffer,
    const uint32_t DeviceIDBufferSize,
    uint32_t* const RequiredSize
);

Tcps_StatusCode
TcpsGetCertChainFromStore(
    const void *Store,
    TCPS_DER_CERT_CHAIN *CertChain
);

#ifdef __cplusplus
}
#endif
