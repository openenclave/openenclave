// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "quote.h"
#include <assert.h>
#include <limits.h>
#include <openenclave/bits/safecrt.h>
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

static oe_result_t _sgx_init_quote_with_aesm(sgx_target_info_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_epid_group_id_t epid_group_id = {{0}};

    aesm_t* aesm = NULL;

    if (!(aesm = aesm_connect()))
        OE_RAISE(OE_FAILURE);

    OE_CHECK(aesm_init_quote(aesm, target_info, &epid_group_id));

    result = OE_OK;

done:

    if (aesm)
        aesm_disconnect(aesm);

    return result;
}

static oe_result_t _sgx_get_quote_size_from_aesm(
    const uint8_t* signature_revocation_list,
    size_t* quote_size)
{
    oe_result_t result = OE_FAILURE;
    size_t signature_size = 0;
    uint32_t n = 0;
    const sgx_sig_rl_t* sig_rl = (const sgx_sig_rl_t*)signature_revocation_list;

    if (quote_size)
        *quote_size = 0;

    if (!quote_size)
        goto done;

    if (sig_rl)
    {
        if (sig_rl->protocol_version != SGX_SE_EPID_SIG_RL_VERSION ||
            sig_rl->epid_identifier != SGX_SE_EPID_SIG_RL_ID)
        {
            goto done;
        }

        assert(sizeof(sig_rl->sig_rl.n2) == sizeof(uint32_t));
        const void* tmp = &sig_rl->sig_rl.n2;
        n = oe_byte_swap32(*(uint32_t*)tmp);
    }

    /* Calculate variable size of EPID_Signature with N entries */
    signature_size =
        sizeof(sgx_epid_signature_t) + (n * sizeof(sgx_epid_nr_proof_t));

    *quote_size = sizeof(sgx_quote_t) + sizeof(sgx_wrap_key_t) +
                  SGX_QUOTE_IV_SIZE + sizeof(uint32_t) + signature_size +
                  SGX_MAC_SIZE;

    result = OE_OK;

done:
    return result;
}

static oe_result_t _sgx_get_quote_from_aesm(
    const sgx_report_t* report,
    sgx_quote_type_t quote_type,
    sgx_quote_t* quote,
    size_t quote_size)
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
    aesm_t* aesm = NULL;

    if (!report || !quote || !quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(aesm = aesm_connect()))
        OE_RAISE(OE_SERVICE_UNAVAILABLE);

    OE_CHECK(aesm_get_quote(
        aesm,
        report,
        quote_type,
        &spid,
        NULL, /* nonce */
        NULL, /* signature_revocation_list */
        0,    /* signature_revocation_list_size */
        NULL, /* report_out */
        quote,
        quote_size));

    result = OE_OK;

done:

    if (aesm)
        aesm_disconnect(aesm);

    return result;
}

#endif

oe_result_t sgx_get_qetarget_info(sgx_target_info_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    memset(target_info, 0, sizeof(sgx_target_info_t));

#if defined(OE_USE_LIBSGX)
    // Quote workflow always begins with obtaining the target info. Therefore
    // initializing the quote provider here ensures that that we can control its
    // life time rather than Intel's attestation libraries.
    // oe_initialize_quote_provider performs initialization only once even if
    // called many times.

    OE_CHECK(oe_initialize_quote_provider());
    OE_CHECK(oe_sgx_qe_get_target_info((uint8_t*)target_info));
#else
    OE_CHECK(_sgx_init_quote_with_aesm(target_info));
#endif

    result = OE_OK;
done:
    return result;
}

oe_result_t sgx_get_quote_size(size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (quote_size)
        *quote_size = 0;

    if (!quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(OE_USE_LIBSGX)
    result = oe_sgx_qe_get_quote_size(quote_size);
#else
    result = _sgx_get_quote_size_from_aesm(NULL, quote_size);
#endif

done:
    return result;
}

oe_result_t sgx_get_quote(
    const sgx_report_t* report,
    uint8_t* quote,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Reject null parameters */
    if (!report || !quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Reject if quote size not big enough even for quote without SigRLs */
    {
        size_t size;
        OE_CHECK(sgx_get_quote_size(&size));

        if (*quote_size < size)
        {
            *quote_size = size;
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
        }

        // Return correct size of the quote.
        *quote_size = size;
    }

    if (!quote)
        OE_RAISE(OE_INVALID_PARAMETER);

    memset(quote, 0, *quote_size);

    /* Get the quote from the AESM service */

#if defined(OE_USE_LIBSGX)

    result = oe_sgx_qe_get_quote((uint8_t*)report, *quote_size, quote);

#else

    result = _sgx_get_quote_from_aesm(
        report,
        SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
        (sgx_quote_t*)quote,
        *quote_size);
#endif

done:

    return result;
}
