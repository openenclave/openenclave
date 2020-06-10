// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_UUID_H
#define _OE_EEID_UUID_H

#include <openenclave/internal/plugin.h>
#include <openenclave/internal/sgx/plugin.h>

#define OE_FORMAT_UUID_SGX_EEID_ECDSA_P256                                \
    {                                                                     \
        0x17, 0x04, 0x94, 0xa6, 0xab, 0x23, 0x47, 0x98, 0x8c, 0x38, 0x35, \
            0x1c, 0xb0, 0xb6, 0xaf, 0x0A                                  \
    }

#endif // _OE_EEID_UUID_H
