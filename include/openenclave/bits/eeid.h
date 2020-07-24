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

#define OE_CLAIM_CONFIG_ID "config_id"
#define OE_CLAIM_CONFIG "config"
#define OE_CLAIM_CONFIG_SVN "config_svn"

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
