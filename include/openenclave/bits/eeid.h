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

/*
**==============================================================================
**
** oe_eeid_t
**
**==============================================================================
*/
typedef struct oe_eeid_t_
{
    uint32_t hash_state_H[8]; /* Hash state before addition of data pages */
    uint32_t hash_state_N[2];
    uint8_t sigstruct[1808]; /* Complete sigstruct before EEID */
    oe_enclave_size_settings_t size_settings; /* New size settings */
    uint64_t vaddr;                           /* Location of EEID */
    uint64_t entry_point;                     /* Enclave entry point */
    uint64_t data_size;                       /* Size of EEID */
    uint8_t data[];                           /* Actual data */
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
    struct _OE_SHA256* cpt_mrenclave);

OE_EXTERNC_END

#endif /* _OE_BITS_EEID_H */
