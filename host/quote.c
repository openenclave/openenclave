#include <limits.h>
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>

OE_Result SGX_InitQuote(
    SGX_TargetInfo* targetInfo,
    SGX_EPIDGroupID* epidGroupID)
{
    OE_Result result = OE_UNEXPECTED;
    AESM* aesm = NULL;

    if (!(aesm = AESMConnect()))
        OE_THROW(OE_FAILURE);

    OE_TRY(AESMInitQuote(aesm, targetInfo, epidGroupID));

    result = OE_OK;

OE_CATCH:

    if (aesm)
        AESMDisconnect(aesm);

    return result;
}

OE_Result SGX_GetQuoteSize(
    const uint8_t* signatureRevocationList,
    size_t* quoteSize)
{
    OE_Result result = OE_FAILURE;
    size_t signatureSize = 0;
    uint64_t n = 0;

    if (quoteSize)
        *quoteSize = 0;

    if (!quoteSize)
        goto done;

    const SGX_SigRL* sigrl = (const SGX_SigRL*)signatureRevocationList;

    if (sigrl)
    {
        if (sigrl->protocolVersion != SGX_SE_EPID_SIG_RL_VERSION ||
            sigrl->epidIdentifier != SGX_SE_EPID_SIG_RL_ID)
        {
            goto done;
        }

        n = OE_ByteSwap32(*(uint32_t*)&sigrl->sigrl.n2);
    }

    /* Calculate variable size of EPID_Signature with N entries */
    signatureSize = sizeof(EPID_Signature) + (n * sizeof(EPID_NRProof));

    *quoteSize = sizeof(SGX_Quote) + sizeof(SGX_WrapKey) + SGX_QUOTE_IV_SIZE +
                 sizeof(uint32_t) + signatureSize + SGX_MAC_SIZE;

    if (*quoteSize > (uint64_t)UINT_MAX)
        goto done;

    result = OE_OK;

done:
    return result;
}

OE_Result SGX_GetQuote(
    const SGX_Report* report,
    SGX_QuoteType quoteType,
    const SGX_SPID* spid,
    const SGX_Nonce* nonce,
    const uint8_t* signatureRevocationList,
    uint32_t signatureRevocationListSize,
    SGX_Report* reportOut,
    SGX_Quote* quote,
    size_t quoteSize)
{
    OE_Result result = OE_UNEXPECTED;
    AESM* aesm = NULL;

    if (!report || !spid || !quote || !quoteSize)
        OE_THROW(OE_INVALID_PARAMETER);

    memset(quote, 0, quoteSize);

    if (reportOut)
        memset(reportOut, 0, sizeof(SGX_Report));

    if (signatureRevocationList && signatureRevocationListSize == 0)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!signatureRevocationList && signatureRevocationListSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!(aesm = AESMConnect()))
        OE_THROW(OE_SERVICE_UNAVAILABLE);

    OE_TRY(
        AESMGetQuote(
            aesm,
            report,
            quoteType,
            spid,
            nonce,
            signatureRevocationList,
            signatureRevocationListSize,
            reportOut,
            quote,
            quoteSize));

    result = OE_OK;

OE_CATCH:

    if (aesm)
        AESMDisconnect(aesm);

    return result;
}

OE_Result OE_GetQuote(
    const void* report,
    size_t reportSize,
    void* quote,
    size_t* quoteSize)
{
    OE_Result result = OE_UNEXPECTED;
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

    /* Reject null parameters */
    if (!report || reportSize != sizeof(SGX_Report) || !quoteSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Reject if quote size not big enough even for quote without SigRLs */
    {
        size_t size;
        OE_TRY(SGX_GetQuoteSize(NULL, &size));

        if (*quoteSize < size)
        {
            *quoteSize = size;
            OE_THROW(OE_BUFFER_TOO_SMALL);
        }
    }

    if (!quote)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Get the quote from the AESM service */
    {
        memset(quote, 0, sizeof(SGX_Quote));

        OE_TRY(
            SGX_GetQuote(
                (const SGX_Report*)report,
                SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
                &spid,
                NULL, /* nonce */
                NULL, /* signature revocation list */
                0,    /* signature revocation list size */
                NULL, /* report out */
                (SGX_Quote*)quote,
                *quoteSize));
    }

    result = OE_OK;

OE_CATCH:

    return result;
}
