// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "quote.h"
#include <assert.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>

#if defined(OE_USE_LIBSGX)
#include <libsgx/sgx_ql_oe_wrapper.h>
#else
#include <openenclave/internal/aesm.h>
#endif

#if !defined(OE_USE_LIBSGX)

static OE_Result _SGX_InitQuoteWithAesm(SGX_TargetInfo* targetInfo)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_EPIDGroupID epidGroupID = {0};

    AESM* aesm = NULL;

    if (!(aesm = AESMConnect()))
        OE_RAISE(OE_FAILURE);

    OE_CHECK(AESMInitQuote(aesm, targetInfo, &epidGroupID));

    result = OE_OK;

done:

    if (aesm)
        AESMDisconnect(aesm);

    return result;
}

static OE_Result _SGX_GetQuoteSizeFromAesm(
    const uint8_t* signatureRevocationList,
    uint32_t* quoteSize)
{
    OE_Result result = OE_FAILURE;
    uint64_t signatureSize = 0;
    uint32_t n = 0;
    uint64_t quoteSize64 = 0;
    const SGX_SigRL* sigrl = (const SGX_SigRL*)signatureRevocationList;

    if (quoteSize)
        *quoteSize = 0;

    if (!quoteSize)
        goto done;

    if (sigrl)
    {
        if (sigrl->protocolVersion != SGX_SE_EPID_SIG_RL_VERSION ||
            sigrl->epidIdentifier != SGX_SE_EPID_SIG_RL_ID)
        {
            goto done;
        }

        assert(sizeof(sigrl->sigrl.n2) == sizeof(uint32_t));
        const void* tmp = &sigrl->sigrl.n2;
        n = OE_ByteSwap32(*(uint32_t*)tmp);
    }

    /* Calculate variable size of EPID_Signature with N entries */
    signatureSize = sizeof(SGX_EPID_Signature) + (n * sizeof(SGX_EPID_NRProof));

    quoteSize64 = sizeof(SGX_Quote) + sizeof(SGX_WrapKey) + SGX_QUOTE_IV_SIZE +
                  sizeof(uint32_t) + signatureSize + SGX_MAC_SIZE;

    if (quoteSize64 > (uint64_t)UINT_MAX)
        goto done;

    *quoteSize = (uint32_t)quoteSize64;
    result = OE_OK;

done:
    return result;
}

static OE_Result _SGX_GetQuoteFromAesm(
    const SGX_Report* report,
    SGX_QuoteType quoteType,
    SGX_Quote* quote,
    size_t quoteSize)
{
    static const SGX_SPID spid = {{
        0x21,
        0x68,
        0x79,
        0xB4,
        0x42,
        0xA0,
        0x4A,
        0x07,
        0x60,
        0xF6,
        0x39,
        0x91,
        0x7F,
        0x4E,
        0x8B,
        0x04,
    }};

    OE_Result result = OE_UNEXPECTED;
    AESM* aesm = NULL;

    if (!report || !quote || !quoteSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(aesm = AESMConnect()))
        OE_RAISE(OE_SERVICE_UNAVAILABLE);

    OE_CHECK(
        AESMGetQuote(
            aesm,
            report,
            quoteType,
            &spid,
            NULL, /* nonce */
            NULL, /* signatureRevocationList */
            0,    /* signatureRevocationListSize */
            NULL, /* reportOut */
            quote,
            quoteSize));

    result = OE_OK;

done:

    if (aesm)
        AESMDisconnect(aesm);

    return result;
}

#endif

OE_Result SGX_GetQETargetInfo(SGX_TargetInfo* targetInfo)
{
    OE_Result result = OE_UNEXPECTED;
    memset(targetInfo, 0, sizeof(*targetInfo));

#if defined(OE_USE_LIBSGX)
    {
        OE_STATIC_ASSERT(sizeof(SGX_TargetInfo) == sizeof(sgx_target_info_t));
        quote3_error_t err =
            sgx_qe_get_target_info((sgx_target_info_t*)targetInfo);
        result = (err == SGX_QL_SUCCESS) ? OE_OK : OE_PLATFORM_ERROR;
    }
#else

    result = _SGX_InitQuoteWithAesm(targetInfo);

#endif

    return result;
}

OE_Result SGX_GetQuoteSize(uint32_t* quoteSize)
{
    OE_Result result = OE_UNEXPECTED;

    if (quoteSize)
        *quoteSize = 0;

    if (!quoteSize)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(OE_USE_LIBSGX)
    {
        quote3_error_t err = sgx_qe_get_quote_size(quoteSize);
        result = (err == SGX_QL_SUCCESS) ? OE_OK : OE_PLATFORM_ERROR;
    }
#else

    result = _SGX_GetQuoteSizeFromAesm(NULL, quoteSize);

#endif

done:
    return result;
}

OE_Result SGX_GetQuote(
    const SGX_Report* report,
    uint8_t* quote,
    uint32_t* quoteSize)
{
    OE_Result result = OE_UNEXPECTED;

    /* Reject null parameters */
    if (!report || !quoteSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Reject if quote size not big enough even for quote without SigRLs */
    {
        uint32_t size;
        OE_CHECK(SGX_GetQuoteSize(&size));

        if (*quoteSize < size)
        {
            *quoteSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        // Return correct size of the quote.
        *quoteSize = size;
    }

    if (!quote)
        OE_RAISE(OE_INVALID_PARAMETER);

    memset(quote, 0, *quoteSize);

/* Get the quote from the AESM service */

#if defined(OE_USE_LIBSGX)
    {
        OE_STATIC_ASSERT(sizeof(SGX_Report) == sizeof(sgx_report_t));
        quote3_error_t err =
            sgx_qe_get_quote((sgx_report_t*)report, *quoteSize, quote);
        result = (err == SGX_QL_SUCCESS) ? OE_OK : OE_PLATFORM_ERROR;
    }
#else

    result = _SGX_GetQuoteFromAesm(
        report,
        SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
        (SGX_Quote*)quote,
        *quoteSize);
#endif

done:

    return result;
}
