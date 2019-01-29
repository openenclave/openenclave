// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRL_H
#define _OE_ENCLAVE_CRL_H

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include <mbedtls/x509_crl.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

#include <openenclave/internal/crl.h>

typedef struct _crl
{
    uint64_t magic;
    mbedtls_x509_crl* crl;
} crl_t;

bool crl_is_valid(const crl_t* impl);

#endif /* _OE_ENCLAVE_CRL_H */
