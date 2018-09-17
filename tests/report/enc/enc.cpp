// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>
#include "../../../common/quote.h"
#include "../../../common/tcbinfo.h"
#include "../common/tests.cpp"
#include "tests_t.h"

oe_result_t test_verify_tcb_info(
    const char* tcb_info,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_tcb_info)
{
#ifdef OE_USE_LIBSGX
    return oe_parse_tcb_info_json(
        (const uint8_t*)tcb_info,
        strlen(tcb_info) + 1,
        platform_tcb_level,
        parsed_tcb_info);
#else
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
