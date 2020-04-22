// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_UUID_H
#define _OE_EEID_UUID_H

#include <openenclave/attestation/plugin.h>

#define OE_EEID_PLUGIN_UUID                                               \
    {                                                                     \
        0x17, 0x04, 0x94, 0xa6, 0xab, 0x23, 0x47, 0x98, 0x8c, 0x38, 0x35, \
            0x1c, 0xb0, 0xb6, 0xaf, 0x0A                                  \
    }

typedef struct
{
    size_t evidence_sz;     /* Size of base-image evidence */
    size_t endorsements_sz; /* Size of base-image endorsements */
    size_t eeid_sz;         /* Size of EEID */
    uint8_t data[];         /* Data (same order as the sizes) */
} eeid_evidence_t;

oe_result_t eeid_on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size);

oe_result_t eeid_on_unregister(oe_attestation_role_t* context);

#endif // _OE_EEID_UUID_H
