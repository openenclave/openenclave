// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "signkey.h"

/* The key for auto-signing debug enclaves */
const uint8_t OE_DEBUG_SIGN_KEY[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "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\n"
    "-----END RSA PRIVATE KEY-----\n";

size_t OE_DEBUG_SIGN_KEY_SIZE = OE_COUNTOF(OE_DEBUG_SIGN_KEY);
