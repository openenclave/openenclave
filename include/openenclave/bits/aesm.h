#ifndef _OE_AESM_H
#define _OE_AESM_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

typedef struct _AESM AESM;
typedef struct _SGX_TargetInfo SGX_TargetInfo;
typedef struct _SGX_EPIDGroupID SGX_EPIDGroupID;

AESM* AESMConnect(void);

void AESMDisconnect(AESM* aesm);

OE_Result AESMGetLaunchToken(
    AESM* aesm,
    uint8_t mrenclave[OE_SHA256_SIZE],
    uint8_t modulus[OE_KEY_SIZE],
    const SGX_Attributes* attributes,
    SGX_LaunchToken* launchToken);

OE_Result AESMInitQuote(
    AESM* aesm,
    SGX_TargetInfo* targetInfo,
    SGX_EPIDGroupID* epidGroupID);

OE_Result AESMGetQuote(
    AESM* aesm,
    const SGX_Report* report,
    SGX_QuoteType quoteType,
    const SGX_SPID* spid,
    const SGX_Nonce* nonce,
    const uint8_t* signatureRevocationList,
    uint32_t signatureRevocationListSize,
    SGX_Report* reportOut,
    SGX_Quote* quote);

OE_EXTERNC_END

#endif /* _OE_AESM_H */
