// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _CUSTOM_CLAIMS_TESTS
#define _CUSTOM_CLAIMS_TESTS

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../common/common.h"

#define CLAIM1_NAME "Claim1"
#define CLAIM1_VALUE "Value1"
#define CLAIM2_NAME "Claim2"
#define CLAIM2_VALUE "Value2"

void _test_custom_claims_seriaize_deserialize();

#endif // _CUSTOM_CLAIMS_TESTS
