// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H_
#define _ARGS_H_

#include <openenclave/bits/types.h>

struct VerifyQuoteArgs
{
    uint8_t* quote;   /* in */
    size_t quoteSize; /* in */

    uint8_t* pemPckCertificate;   /* in */
    size_t pemPckCertificateSize; /* in */

    uint8_t* pckCrl;   /* in */
    size_t pckCrlSize; /* in */

    uint8_t* tcbInfoJson;   /* in */
    size_t tcbInfoJsonSize; /* in */

    oe_result_t result; /* out */
};

struct VerifyTCBInfoArgs
{
    uint8_t* tcbInfo;       /* in */
    size_t tcbInfoSize;     /* in */
    void* platformTcbLevel; /* in */
    void* parsedTcbInfo;    /* out */
    oe_result_t result;     /* out */
};

struct ParseJsonArgs
{
    uint8_t* json;      /* in */
    size_t jsonSize;    /* in */
    oe_result_t result; /* out */
};

#endif //_ARGS_H_
