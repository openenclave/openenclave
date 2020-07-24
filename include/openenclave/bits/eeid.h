// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file eeid.h
 *
 * This file defines the EEID structure.
 *
 */

#ifndef _OE_BITS_EEID_H
#define _OE_BITS_EEID_H

#ifdef OE_WITH_EXPERIMENTAL_EEID

#include "properties.h"

OE_EXTERNC_BEGIN

#define OE_EEID_VERSION (2)

#define OE_CLAIM_CONFIG_ID "config_id"
#define OE_CLAIM_CONFIG "config"
#define OE_CLAIM_CONFIG_SVN "config_svn"

OE_PACK_BEGIN
/**
 * Structure to keep all information relevant to EEID.
 */
typedef struct _oe_eeid
{
    /** Version number of the oe_eeid_t structure. */
    uint32_t version;

    /** Internal state of the hash computation at the end of the enclave base
     * image. */
    struct
    {
        /** Internal hash state. */
        uint32_t H[8];

        /** Number of bytes hashed. */
        uint32_t N[2];
    } hash_state;

    /** Heap, stack, and thread configuration for an EEID enclave instance. */
    oe_enclave_size_settings_t size_settings;

    /** Identity of the config/code/data to be loaded into the enclave after
     * enclave init */
    uint8_t config_id[32];

    /** Minimum SVN of the config/code/data to be loaded into the enclave after
     * enclave init */
    uint16_t config_svn;

    /** Location of the added data pages in enclave memory. */
    uint64_t vaddr;

    /** Entry point of the image. */
    uint64_t entry_point;

    /** Size of the signature in bytes. */
    uint64_t signature_size;

    /** Buffer holding the signature. */
    uint8_t signature[];
} oe_eeid_t;
OE_PACK_END

/**
 * Structure to keep EEID related options during enclave creation
 */
typedef struct _oe_enclave_setting_eeid
{
    /** Heap, stack, and thread configuration for an EEID enclave instance. */
    oe_enclave_size_settings_t size_settings;

    /** Config ID */
    uint8_t config_id[32];
    uint16_t config_svn;

    /** EEID Data */
    size_t data_size;
    uint8_t data[];
} oe_enclave_setting_eeid_t;

OE_EXTERNC_END

#endif /* OE_WITH_EXPERIMENTAL_EEID */

#endif /* _OE_BITS_EEID_H */
