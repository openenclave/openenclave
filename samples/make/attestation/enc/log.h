#ifndef OE_SAMPLES_ATTESTATION_ENC_LOG_H
#define OE_SAMPLES_ATTESTATION_ENC_LOG_H

#include <openenclave/enclave.h>

/**
 * Use OE_HostPrintf function to print log messages from the enclave.
 * Turn on logging during development and turn off in production.
 */

#ifndef ENABLE_LOGGING
#define ENABLE_LOGGING 1
#endif

#if (ENABLE_LOGGING)

#define ENC_DEBUG_PRINTF(fmt, ...) \
    OE_HostPrintf("***%s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#else

#define ENC_DEBUG_PRINTF(...)

#endif

#endif // OE_SAMPLES_ATTESTATION_ENC_LOG_H
