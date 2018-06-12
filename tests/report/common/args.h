// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H_
#define _ARGS_H_

#include <openenclave/bits/types.h>

struct VerifyQuoteArgs
{
    uint8_t* quote;     /* in */
    uint32_t quoteSize; /* in */

    uint8_t* pemPckCertificate;     /* in */
    uint32_t pemPckCertificateSize; /* in */

    uint8_t* pckCrl;     /* in */
    uint32_t pckCrlSize; /* in */

    uint8_t* tcbInfoJson;     /* in */
    uint32_t tcbInfoJsonSize; /* in */

    OE_Result result; /* out */
};

#endif //_ARGS_H_
