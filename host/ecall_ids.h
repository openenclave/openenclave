// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_ECALLIDS_H
#define _OE_HOST_ECALLIDS_H

#include <openenclave/edger8r/host.h>
#include <openenclave/host.h>

#define OE_ECALL_ID_NULL OE_UINT64_MAX
#define OE_MAX_ECALLS 256

OE_EXTERNC_BEGIN

/**
 * Id of an ecall.
 */
typedef struct _oe_ecall_id_t
{
    uint64_t id;
} oe_ecall_id_t;

/**
 * Get the global id for a given ecall name.
 */
oe_result_t oe_get_global_id(
    const char* name,     /* in */
    uint64_t* global_id); /* out */

/**
 * Set the ecall id table for an enclave.
 * This function is expected to be implemented as appropriate by
 * host platform layers for various TEEs (SGX, OPTEE etc).
 */
oe_result_t oe_set_ecall_id_table(
    oe_enclave_t* enclave,         /* in */
    oe_ecall_id_t* ecall_id_table, /* in */
    uint64_t ecall_id_table_size); /* in */

/**
 * Given an enclave, return its ecall id table.
 * The ecall id table maps an ecall's global id to its function id.
 * This function is expected to be implemented as appropriate by
 * host platform layers for varios TEEs (SGX, OPTEE etc).
 */
oe_result_t oe_get_ecall_id_table(
    oe_enclave_t* enclave,          /* in */
    oe_ecall_id_t** ecall_id_table, /* out */
    uint64_t* ecall_id_table_size); /* out */

/**
 * Get the ecall ids (global and local/function) of an ecall, given its
 * name and enclave.
 */
oe_result_t oe_get_ecall_ids(
    oe_enclave_t* enclave, /* in */
    const char* name,      /* in */
    uint64_t* global_id,   /* in/out */
    uint64_t* id);         /* out */

/**
 * Register the ecalls for a given enclave.
 */
oe_result_t oe_register_ecalls(
    oe_enclave_t* enclave,                   /* in */
    const oe_ecall_info_t* ecall_info_table, /* in */
    uint32_t num_ecalls);                    /* in */

OE_EXTERNC_END

#endif /* _OE_HOST_ECALL_IDS_H */
