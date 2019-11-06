// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/crl.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

#include "../magic.h"
#include "bcrypt.h"
#include "crl.h"

typedef struct _crl
{
    uint64_t magic;
    PCCRL_CONTEXT crl;
} crl_t;

OE_STATIC_ASSERT(sizeof(crl_t) <= sizeof(oe_crl_t));

OE_INLINE void _crl_init(crl_t* impl, PCCRL_CONTEXT crl_context)
{
    impl->magic = OE_CRL_MAGIC;
    impl->crl = crl_context;
}

OE_INLINE bool _crl_is_valid(const crl_t* impl)
{
    return impl && (impl->magic == OE_CRL_MAGIC) && impl->crl;
}

OE_INLINE void _crl_destroy(crl_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->crl = NULL;
    }
}

oe_result_t oe_crl_get_context(const oe_crl_t* crl, PCCRL_CONTEXT* crl_context)
{
    oe_result_t result = OE_UNEXPECTED;
    const crl_t* impl = (const crl_t*)crl;

    if (crl_context)
        *crl_context = NULL;

    if (!_crl_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    *crl_context = impl->crl;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_crl_read_der(
    oe_crl_t* crl,
    const uint8_t* der_data,
    size_t der_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;

    /* Clear the implementation */
    if (impl)
        memset(impl, 0, sizeof(crl_t));

    /* Check for invalid parameters */
    if (!der_data || !der_data_size || der_data_size > OE_INT_MAX || !crl)
        OE_RAISE(OE_INVALID_PARAMETER);

    PCCRL_CONTEXT crl_context =
        CertCreateCRLContext(X509_ASN_ENCODING, der_data, (DWORD)der_data_size);

    if (!crl_context)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CertCreateCRLContext failed, err=%#x\n",
            GetLastError());

    impl->magic = OE_CRL_MAGIC;
    impl->crl = crl_context;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_crl_free(oe_crl_t* crl)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;

    if (!_crl_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    CertFreeCRLContext(impl->crl);
    _crl_destroy(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_crl_get_update_dates(
    const oe_crl_t* crl,
    oe_datetime_t* last,
    oe_datetime_t* next)
{
    oe_result_t result = OE_UNEXPECTED;
    const crl_t* impl = (const crl_t*)crl;

    if (last)
        memset(last, 0, sizeof(oe_datetime_t));

    if (next)
        memset(next, 0, sizeof(oe_datetime_t));

    if (!_crl_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    PCRL_INFO crl_info = impl->crl->pCrlInfo;

    if (last)
        OE_CHECK(oe_util_filetime_to_oe_datetime(&crl_info->ThisUpdate, last));

    if (next)
        OE_CHECK(oe_util_filetime_to_oe_datetime(&crl_info->NextUpdate, next));

    result = OE_OK;

done:
    return result;
}
