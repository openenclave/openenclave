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

#include "properties.h"

OE_EXTERNC_BEGIN

#ifdef OE_WITH_EXPERIMENTAL_EEID
/*
**==============================================================================
**
** oe_eeid_t
**
**==============================================================================
*/
typedef struct oe_eeid_t_
{
    struct
    {
        uint32_t H[8];
        uint32_t N[2];
    } hash_state; /* internal state of the hash computation at the end of
                           the enclave base image */
    uint64_t signature_size; /* size of signature */
    uint8_t signature[1808]; /* base-image signature and associated data (for
                           SGX, the complete sigstruct of the base image) */
    oe_enclave_size_settings_t
        size_settings; /* heap, stack and thread configuration for this instance
                        */
    uint64_t vaddr; /* location of the added data pages in enclave memory; EEID
                       follows immediately thereafter */
    uint64_t entry_point; /* entry point of the image */
    uint64_t data_size;   /* size of application EEID */
    uint8_t data[];       /* actual application EEID */
} oe_eeid_t;

oe_result_t oe_serialize_eeid(
    const oe_eeid_t* eeid,
    char* buf,
    size_t buf_size);

oe_result_t oe_deserialize_eeid(
    const char* buf,
    size_t buf_size,
    oe_eeid_t* eeid);

struct _OE_SHA256;

oe_result_t oe_replay_eeid_pages(
    const oe_eeid_t* eeid,
    struct _OE_SHA256* cpt_mrenclave,
    bool with_eeid_page);

oe_result_t verify_eeid(
    const uint8_t* r_mrenclave,
    const uint8_t* r_mrsigner,
    uint16_t r_product_id,
    uint32_t r_security_version,
    uint64_t r_attributes,
    const oe_eeid_t* eeid);

#endif /* OE_WITH_EXPERIMENTAL_EEID */

OE_EXTERNC_END

#endif /* _OE_BITS_EEID_H */
