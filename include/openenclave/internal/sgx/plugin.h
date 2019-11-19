// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_PLUGIN
#define _OE_INTERNAL_SGX_PLUGIN

#include <openenclave/bits/report.h>

/**
 * The SGX plugin UUID.
 */
#define OE_SGX_PLUGIN_UUID                                                \
    {                                                                     \
        0xa3, 0xa2, 0x1e, 0x87, 0x1b, 0x4d, 0x40, 0x14, 0xb7, 0x0a, 0xa1, \
            0x25, 0xd2, 0xfb, 0xcd, 0x8c                                  \
    }

#define OE_SGX_PLUGIN_CLAIMS_VERSION 1

/**
 *  Serialized header for the custom claims.
 */
typedef struct _oe_sgx_plugin_claims_header
{
    uint64_t version;
    uint64_t num_claims;
} oe_sgx_plugin_claims_header_t;

/**
 * Serialzied entry for custom claims. Each entry will have the name and value
 * sizes and then the contents of the name and value respectively.
 */
typedef struct _oe_sgx_plugin_claims_entry
{
    uint64_t name_size;
    uint64_t value_size;
    uint8_t name[];
    // name_size bytes follow.
    // value_size_bytes follow.
} oe_sgx_plugin_claims_entry_t;

#endif // _OE_INTENRAL_SGX_PLUGIN
