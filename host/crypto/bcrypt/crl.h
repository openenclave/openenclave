// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_CRL_H
#define _OE_HOST_CRYPTO_CRL_H

#include <openenclave/internal/crypto/crl.h>
#include "bcrypt.h"

oe_result_t oe_crl_get_context(const oe_crl_t* crl, PCCRL_CONTEXT* crl_context);

#endif /* _OE_HOST_CRYPTO_CRL_H */
