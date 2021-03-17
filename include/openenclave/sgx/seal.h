// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file
 *
 * This file defines SGX specific constants and structures for sealing APIs.
 *
 * Only SGX specific definitions should go here, while TEE generic definitions
 * should go in bits/seal.h
 *
 */
#ifndef _OE_SGX_SEAL_H
#define _OE_SGX_SEAL_H

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/seal.h>

OE_EXTERNC_BEGIN

/**
 * SGX specific seal settings.
 */
enum oe_seal_setting_type_sgx_t
{
    OE_SEAL_SETTING_SGX_KEYNAME = OE_SEAL_SETTING_PLUGIN_DEFINED,
    OE_SEAL_SETTING_SGX_ISVSVN,
    OE_SEAL_SETTING_SGX_CET_ATTRIBUTES_MASK,
    OE_SEAL_SETTING_SGX_CPUSVN,
    OE_SEAL_SETTING_SGX_FLAGSMASK,
    OE_SEAL_SETTING_SGX_XFRMMASK,
    OE_SEAL_SETTING_SGX_MISCMASK,
    OE_SEAL_SETTING_SGX_CONFIGSVN,

    /**
     * Lower bound of plug-in defined setting types.
     */
    OE_SEAL_SETTING_SGX_PLUGIN_DEFINED =
        OE_SEAL_SETTING_PLUGIN_DEFINED + OE_SEAL_SETTING_PLUGIN_DEFINED / 2
};

/**
 * Initialize a \c oe_seal_setting_t structure to specify \c
 * KEYREQUEST.KEYNAME.
 *
 * @param[in] w 16-bit value to be assigned to \c KEYREQUEST.KEYNAME.
 */
#define OE_SEAL_SET_SGX_KEYNAME(w) \
    __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_SGX_KEYNAME, w)

/**
 * Initialize a \c oe_seal_setting_t structure to specify \c
 * KEYREQUEST.ISVSVN.
 *
 * @param[in] w 16-bit value to be assigned to \c KEYREQUEST.ISVSVN.
 */
#define OE_SEAL_SET_SGX_ISVSVN(w) \
    __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_SGX_ISVSVN, w)

/**
 * Initialize a \c oe_seal_setting_t structure to specify \c
 * KEYREQUEST.CET_ATTRIBUTES_MASK.
 *
 * @param[in] b 8-bit value to be assigned to \c KEYREQUEST.CET_ATTRIBUTES_MASK.
 */
#define OE_SEAL_SET_SGX_CET_ATTRIBUTES_MASK(b) \
    __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_SGX_CET_ATTRIBUTES_MASK, b)

/**
 * Initialize a \c oe_seal_setting_t structure to specify \c
 * KEYREQUEST.CPUSVN.
 *
 * @param[in] p Points to a 16-byte array to be assigned to \c
 * KEYREQUEST.CPUSVN.
 */
#define OE_SEAL_SET_SGX_CPUSVN(p) \
    __OE_SEAL_SET_POINTER(OE_SEAL_SETTING_SGX_CPUSVN, p, 16)

/**
 * Initialize a \c oe_seal_setting_t structure to specify the low 64 bits of \c
 * KEYREQUEST.ATTRIBYTEMASK.
 *
 * @param[in] q 64-bit value to be assigned to low 64 bits of \c
 * KEYREQUEST.ATTRIBYTEMASK.
 */
#define OE_SEAL_SET_SGX_FLAGSMASK(q) \
    __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_SGX_FLAGSMASK, q)

/**
 * Initialize a \c oe_seal_setting_t structure to specify the high 64 bits of
 * \c KEYREQUEST.ATTRIBYTEMASK.
 *
 * @param[in] q 64-bit value to be assigned to high 64 bits of \c
 * KEYREQUEST.ATTRIBYTEMASK.
 */
#define OE_SEAL_SET_SGX_XFRMMASK(q) \
    __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_SGX_XFRMMASK, q)

/**
 * Initialize a \c oe_seal_setting_t structure to specify \c
 * KEYREQUEST.MISCMASK.
 *
 * @param[in] d 32-bit value to be assigned to \c KEYREQUEST.MISCMASK.
 */
#define OE_SEAL_SET_SGX_MISCMASK(d) \
    __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_SGX_MISCMASK, d)

/**
 * Initialize a \c oe_seal_setting_t structure to specify \c
 * KEYREQUEST.CONFIGSVN.
 *
 * @param[in] w 16-bit value to be assigned to \c KEYREQUEST.CONFIGSVN.
 */
#define OE_SEAL_SET_SGX_CONFIGSVN(w) \
    __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_SGX_CPUSVN, w)

/**
 * Built-in seal plug-in based on GCM-AES
 */
extern const oe_seal_plugin_definition_t oe_seal_plugin_gcm_aes;

OE_EXTERNC_END

#endif /* _OE_SGX_SEAL_H */
