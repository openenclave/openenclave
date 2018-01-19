#include <openenclave/host.h>
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>

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

OE_Result SGX_GetQuote(
    const SGX_Report* report,
    SGX_QuoteType quoteType,
    const SGX_SPID* spid,
    const SGX_Nonce* nonce,
    const uint8_t* signatureRevocationList,
    uint32_t signatureRevocationListSize,
    SGX_Report* reportOut,
    SGX_Quote* quote,
    uint32_t quoteSize)
{
    OE_Result result = OE_UNEXPECTED;
    AESM* aesm = NULL;

    if (!report || !spid || !quote || !quoteSize)
        OE_THROW(OE_INVALID_PARAMETER);

#if 0
    memset(quote, 0, quoteSize);
#endif

    if (reportOut)
        memset(reportOut, 0, sizeof(SGX_Report));

    if (signatureRevocationList && signatureRevocationListSize == 0)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!signatureRevocationList && signatureRevocationListSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!(aesm = AESMConnect()))
        OE_THROW(OE_SERVICE_UNAVAILABLE);

    OE_TRY(AESMGetQuote(
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
    static const SGX_SPID spid =
    {
        {
            0x21, 0x68, 0x79, 0xB4, 0x42, 0xA0, 0x4A, 0x07,
            0x60, 0xF6, 0x39, 0x91, 0x7F, 0x4E, 0x8B, 0x04,
        }
    };

    /* Reject null parameters */
    if (!report || reportSize != sizeof(SGX_Report) || !quoteSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Reject if quote size not big enough */
    if (*quoteSize < sizeof(SGX_Quote))
    {
        *quoteSize = sizeof(SGX_Quote);
        OE_THROW(OE_BUFFER_TOO_SMALL);
    }

    if (!quote)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Get the quote from the AESM service */
    {
        *quoteSize = sizeof(SGX_Quote);
        memset(quote, 0, sizeof(SGX_Quote));

        OE_TRY(SGX_GetQuote(
            (const SGX_Report*)report,
            SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
            &spid,
            NULL, /* nonce */
            NULL, /* signature revocation list */
            0, /* signature revocation list size */
            NULL, /* report out */
            (SGX_Quote*)quote,
            sizeof(SGX_Quote)));
    }

    result = OE_OK;

OE_CATCH:

    return result;
}
