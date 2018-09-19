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
#include "sgxquote.h"
#include "sgxquoteprovider.h"
#else
#include <openenclave/internal/aesm.h>
#endif

#if !defined(OE_USE_LIBSGX)

static oe_result_t _sgx_init_quote_with_aesm(sgx_target_info_t* targetInfo)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_epid_group_id_t epidGroupID = {{0}};

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

static oe_result_t _sgx_get_quote_size_from_aesm(
    const uint8_t* signatureRevocationList,
    size_t* quoteSize)
{
    oe_result_t result = OE_FAILURE;
    size_t signatureSize = 0;
    uint32_t n = 0;
    const sgx_sig_rl_t* sigrl = (const sgx_sig_rl_t*)signatureRevocationList;

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
        n = oe_byte_swap32(*(uint32_t*)tmp);
    }

    /* Calculate variable size of EPID_Signature with N entries */
    signatureSize =
        sizeof(sgx_epid_signature_t) + (n * sizeof(sgx_epid_nr_proof_t));

    *quoteSize = sizeof(sgx_quote_t) + sizeof(sgx_wrap_key_t) +
                 SGX_QUOTE_IV_SIZE + sizeof(uint32_t) + signatureSize +
                 SGX_MAC_SIZE;

    result = OE_OK;

done:
    return result;
}

static oe_result_t _sgx_get_quote_from_aesm(
    const sgx_report_t* report,
    sgx_quote_type_t quoteType,
    sgx_quote_t* quote,
    size_t quoteSize)
{
    static const sgx_spid_t spid = {{
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

    oe_result_t result = OE_UNEXPECTED;
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

oe_result_t sgx_get_qetarget_info(sgx_target_info_t* targetInfo)
{
    oe_result_t result = OE_UNEXPECTED;
    memset(targetInfo, 0, sizeof(*targetInfo));

#if defined(OE_USE_LIBSGX)
    // Quote workflow always begins with obtaining the target info. Therefore
    // initializing the quote provider here ensures that that we can control its
    // life time rather than Intel's attestation libraries.
    // oe_initialize_quote_provider performs initialization only once even if
    // called many times.

    oe_initialize_quote_provider();
    result = oe_sgx_qe_get_target_info((uint8_t*)targetInfo);

#else

    result = _sgx_init_quote_with_aesm(targetInfo);

#endif

    return result;
}

oe_result_t sgx_get_quote_size(size_t* quoteSize)
{
    oe_result_t result = OE_UNEXPECTED;

    if (quoteSize)
        *quoteSize = 0;

    if (!quoteSize)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(OE_USE_LIBSGX)

    result = oe_sgx_qe_get_quote_size(quoteSize);

#else

    result = _sgx_get_quote_size_from_aesm(NULL, quoteSize);

#endif

done:
    return result;
}

oe_result_t sgx_get_quote(
    const sgx_report_t* report,
    uint8_t* quote,
    size_t* quoteSize)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Reject null parameters */
    if (!report || !quoteSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Reject if quote size not big enough even for quote without SigRLs */
    {
        size_t size;
        OE_CHECK(sgx_get_quote_size(&size));

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

    result = oe_sgx_qe_get_quote((uint8_t*)report, *quoteSize, quote);

#else

    result = _sgx_get_quote_from_aesm(
        report,
        SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
        (sgx_quote_t*)quote,
        *quoteSize);
#endif

done:

    return result;
}
