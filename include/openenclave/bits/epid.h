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

#include <openenclave/defs.h>
#include <openenclave/types.h>

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
typedef struct _SGX_EPID_OctStr32
{
    uint8_t data[32 / 8];
} SGX_EPID_OctStr32;
OE_PACK_END

/* 256-bit octet string */
OE_PACK_BEGIN
typedef struct _SGX_EPID_OctStr256
{
    uint8_t data[256 / 8];
} SGX_EPID_OctStr256;
OE_PACK_END

/*
**==============================================================================
**
** SGX_EPID_FqElemStr
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_FqElemStr
{
    SGX_EPID_OctStr256 data;
} SGX_EPID_FqElemStr;
OE_PACK_END

/*
**==============================================================================
**
** SGX_EPID_FpElemStr
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_FpElemStr
{
    SGX_EPID_OctStr256 data;
} SGX_EPID_FpElemStr;
OE_PACK_END

/*
**==============================================================================
**
** SGX_EPID_G1ElemStr
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_G1ElemStr
{
    SGX_EPID_FqElemStr x;
    SGX_EPID_FqElemStr y;
} SGX_EPID_G1ElemStr;
OE_PACK_END

/*
**==============================================================================
**
** SGX_EPID_BasicSignature
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_BasicSignature
{
    SGX_EPID_G1ElemStr B;
    SGX_EPID_G1ElemStr K;
    SGX_EPID_G1ElemStr T;
    SGX_EPID_FpElemStr c;
    SGX_EPID_FpElemStr sx;
    SGX_EPID_FpElemStr sf;
    SGX_EPID_FpElemStr sa;
    SGX_EPID_FpElemStr sb;
} SGX_EPID_BasicSignature;
OE_PACK_END

/*
**==============================================================================
**
** SGX_EPID_NRProof
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_NRProof
{
    SGX_EPID_G1ElemStr T;
    SGX_EPID_FpElemStr c;
    SGX_EPID_FpElemStr smu;
    SGX_EPID_FpElemStr snu;

} SGX_EPID_NRProof;
OE_PACK_END

/*
**==============================================================================
**
** _SGX_EPID_Signature
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_Signature
{
    /* Basic signature */
    SGX_EPID_BasicSignature sigma0;

    /* Revocation list version number */
    SGX_EPID_OctStr32 rl_ver;

    /* number of entries in SigRL */
    SGX_EPID_OctStr32 n2;

    /* array of non-revoked proofs (variable length array) */
    OE_ZERO_SIZED_ARRAY SGX_EPID_NRProof sigma[0];

} SGX_EPID_Signature;
OE_PACK_END

/*
**==============================================================================
**
** _SGX_EPID_SigRLEntry
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_SigRLEntry
{
    SGX_EPID_G1ElemStr b;
    SGX_EPID_G1ElemStr k;
} SGX_EPID_SigRLEntry;
OE_PACK_END

/*
**==============================================================================
**
** _SGX_EPID_SigRLEntry
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_EPID_SigRL
{
    /* Group identifier */
    SGX_EPID_OctStr32 gid[4];

    /* Revocation list number */
    uint8_t rlver[4];

    /* Number of entries */
    uint8_t n2[4];

    /* SigRL entries */
    SGX_EPID_SigRLEntry bk[1];
} SGX_EPID_SigRL;
OE_PACK_END

OE_EXTERNC_END

#endif /* _OE_EPID_H */
