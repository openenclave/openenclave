// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file attestation.h
 *
 * This file defines structures and options passed to attestation functions.
 *
 */
#ifndef _OE_BITS_ATTESTATION_H
#define _OE_BITS_ATTESTATION_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

/**
 * Flags passed to oe_get_evidence() function.
 */
#define OE_EVIDENCE_FLAGS_LOCAL_ATTESTATION 0x00000000
#define OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION 0x00000001

/*! Limit the size of the endorsements */
#define OE_ATTESTATION_ENDORSEMENT_MAX_SIZE (20 * 1024)

/*! Endorsement structure version */
#define OE_ATTESTATION_ENDORSEMENT_VERSION (1)

/*! \struct oe_endorsements_t
 *
 * \brief OE endorsements
 *
 * Raw generic serializable structure that contains the endorsements. All
 * data should be in little endian format.
 *
 */
typedef struct _oe_endorsements_t
{
    uint32_t version;      ///< Version of this structure
    uint32_t enclave_type; ///< The type of enclave (oe_enclave_type_t)
    uint32_t buffer_size;  ///< Size of the buffer
    uint32_t num_elements; ///< Number of elements stored in the data buffer

    /*! Data buffer is made of an offset array of type uint32_t, followed by
     * the actual data.
     * This array has the size of **num_elements** and stores the offset
     * into the data section.
     * _________________________
     * |  version              |
     * |-----------------------|
     * |  enclave_type         |
     * |-----------------------|
     * |  buffer_size          |
     * |-----------------------|
     * |  num_elements         |
     * |-----------------------|
     * |  offsets              |
     * |  (array of uint32_t   |
     * |  with length of       |
     * |  num_elements)        |
     * |-----------------------|
     * |  buffer (data)        |
     * |_______________________|
     */
    uint8_t buffer[]; ///< Buffer of offsets + data

} oe_endorsements_t;
/**< typedef struct _oe_endorsements_t */

/*! Version of the supported SGX endorsement structures */
#define OE_SGX_ENDORSEMENTS_VERSION (1)

/*! Number of CRLs in the SGX endorsements */
#define OE_SGX_ENDORSEMENTS_CRL_COUNT (2)

/*! \enum oe_sgx_endorsements_fields
 *
 * Specifies the order of the SGX endorsements fields stored in
 * the oe_endorsements_t structure
 */
typedef enum _oe_sgx_endorsements_fields_t
{
    OE_SGX_ENDORSEMENT_FIELD_VERSION,
    OE_SGX_ENDORSEMENT_FIELD_TCB_INFO,
    OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN,
    OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT,
    OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA,
    OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT,
    OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO,
    OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN,
    OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME,
    OE_SGX_ENDORSEMENT_COUNT

} oe_sgx_endorsements_fields_t;

#endif /* _OE_BITS_ATTESTATION_H */
