// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
**==============================================================================
**
** epid.h
**
**     Definition of the SGX SGX_EPID_ data types.
**
**==============================================================================
*/

#ifndef _OE_EPID_H
#define _OE_EPID_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** Octet strings of various powers of two
**
**==============================================================================
*/

/* 32-bit octet string */
OE_PACK_BEGIN
typedef struct _sgx_epid_oct_str32
{
    uint8_t data[32 / 8];
} sgx_epid_oct_str32_t;
OE_PACK_END

/* 256-bit octet string */
OE_PACK_BEGIN
typedef struct _sgx_epid_oct_str256
{
    uint8_t data[256 / 8];
} sgx_epid_oct_str256_t;
OE_PACK_END

/*
**==============================================================================
**
** sgx_epid_fq_elem_str_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_fq_elem_str
{
    sgx_epid_oct_str256_t data;
} sgx_epid_fq_elem_str_t;
OE_PACK_END

/*
**==============================================================================
**
** sgx_epid_fp_elem_str_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_fp_elem_str
{
    sgx_epid_oct_str256_t data;
} sgx_epid_fp_elem_str_t;
OE_PACK_END

/*
**==============================================================================
**
** sgx_epid_g1_elem_str_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_g1_elem_str
{
    sgx_epid_fq_elem_str_t x;
    sgx_epid_fq_elem_str_t y;
} sgx_epid_g1_elem_str_t;
OE_PACK_END

/*
**==============================================================================
**
** sgx_epid_basic_signature_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_basic_signature
{
    sgx_epid_g1_elem_str_t B;
    sgx_epid_g1_elem_str_t K;
    sgx_epid_g1_elem_str_t T;
    sgx_epid_fp_elem_str_t c;
    sgx_epid_fp_elem_str_t sx;
    sgx_epid_fp_elem_str_t sf;
    sgx_epid_fp_elem_str_t sa;
    sgx_epid_fp_elem_str_t sb;
} sgx_epid_basic_signature_t;
OE_PACK_END

/*
**==============================================================================
**
** sgx_epid_nr_proof_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_nr_proof
{
    sgx_epid_g1_elem_str_t T;
    sgx_epid_fp_elem_str_t c;
    sgx_epid_fp_elem_str_t smu;
    sgx_epid_fp_elem_str_t snu;

} sgx_epid_nr_proof_t;
OE_PACK_END

/*
**==============================================================================
**
** _sgx_epid_signature
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_signature
{
    /* Basic signature */
    sgx_epid_basic_signature_t sigma0;

    /* Revocation list version number */
    sgx_epid_oct_str32_t rl_ver;

    /* number of entries in sig_rl */
    sgx_epid_oct_str32_t n2;

    /* array of non-revoked proofs (variable length array) */
    OE_ZERO_SIZED_ARRAY sgx_epid_nr_proof_t sigma[0];

} sgx_epid_signature_t;
OE_PACK_END

/*
**==============================================================================
**
** _sgx_epid_sig_rl_entry
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_sig_rl_entry
{
    sgx_epid_g1_elem_str_t b;
    sgx_epid_g1_elem_str_t k;
} sgx_epid_sig_rl_entry_t;
OE_PACK_END

/*
**==============================================================================
**
** _sgx_epid_sig_rl_entry
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_epid_sig_rl
{
    /* Group identifier */
    sgx_epid_oct_str32_t gid[4];

    /* Revocation list number */
    uint8_t rlver[4];

    /* Number of entries */
    uint8_t n2[4];

    /* sig_rl entries */
    sgx_epid_sig_rl_entry_t bk[1];
} sgx_epid_sig_rl_t;
OE_PACK_END

OE_EXTERNC_END

#endif /* _OE_EPID_H */
