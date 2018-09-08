// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_LOG_H
#define OE_SAMPLES_ATTESTATION_ENC_LOG_H

#include <stdio.h>

/**
 * Use printf function to print log messages from the enclave via the host.
 * Turn on logging during development and turn off in production.
 */

#ifndef ENABLE_LOGGING
#define ENABLE_LOGGING 1
#endif

#if (ENABLE_LOGGING)

#define ENC_DEBUG_PRINTF(fmt, ...) \
    printf("***%s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#else

#define ENC_DEBUG_PRINTF(...)

#endif

#endif // OE_SAMPLES_ATTESTATION_ENC_LOG_H
