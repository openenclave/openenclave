// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>
#include "../../../common/sgx/quote.h"
#include "../../../common/sgx/tcbinfo.h"
#include "tests_t.h"

oe_result_t test_verify_qe_identity_info(
    const char* info_json,
    oe_qe_identity_info_tcb_level_t* platform_tcb_level,
    oe_parsed_qe_identity_info_t* parsed_info)
{
    return oe_parse_qe_identity_info_json(
        (const uint8_t*)info_json,
        strlen(info_json) + 1,
        platform_tcb_level,
        parsed_info);
}

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
