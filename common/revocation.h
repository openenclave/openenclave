// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_REVOCATION_H
#define _OE_COMMON_REVOCATION_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>

oe_result_t OE_EnforceRevocation(
    oe_cert_t* intermediateCert,
    oe_cert_t* leafCert);

#endif // _OE_COMMON_REVOCATION_H
