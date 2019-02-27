// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>
#include "../../../common/sgx/quote.h"
#include "../../../common/sgx/tcbinfo.h"
#include "tests_t.h"

oe_result_t test_verify_qe_identity_info(
    const char* info_json,
    oe_parsed_qe_identity_info_t* parsed_info)
{
#ifdef OE_USE_LIBSGX
    return oe_parse_qe_identity_info_json(
        (const uint8_t*)info_json, strlen(info_json) + 1, parsed_info);
#else
    OE_UNUSED(info_json);
    OE_UNUSED(parsed_info);
    return OE_OK;
#endif
}

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
