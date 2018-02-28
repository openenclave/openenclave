/*
**==============================================================================
**
** epid.h
**
**     Definition of the SGX EPID data types.
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
typedef struct _EPID_OctStr32
{
    uint8_t data[32 / 8];
} EPID_OctStr32;
OE_PACK_END

/* 256-bit octet string */
OE_PACK_BEGIN
typedef struct _EPID_OctStr256
{
    uint8_t data[256 / 8];
} EPID_OctStr256;
OE_PACK_END

/*
**==============================================================================
**
** EPID_FqElemStr
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_FqElemStr
{
    EPID_OctStr256 data;
} EPID_FqElemStr;
OE_PACK_END

/*
**==============================================================================
**
** EPID_FpElemStr
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_FpElemStr
{
    EPID_OctStr256 data;
} EPID_FpElemStr;
OE_PACK_END

/*
**==============================================================================
**
** EPID_G1ElemStr
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_G1ElemStr
{
    EPID_FqElemStr x;
    EPID_FqElemStr y;
} EPID_G1ElemStr;
OE_PACK_END

/*
**==============================================================================
**
** EPID_BasicSignature
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_BasicSignature
{
    EPID_G1ElemStr B;
    EPID_G1ElemStr K;
    EPID_G1ElemStr T;
    EPID_FpElemStr c;
    EPID_FpElemStr sx;
    EPID_FpElemStr sf;
    EPID_FpElemStr sa;
    EPID_FpElemStr sb;
} EPID_BasicSignature;
OE_PACK_END

/*
**==============================================================================
**
** EPID_NRProof
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_NRProof
{
    EPID_G1ElemStr T;
    EPID_FpElemStr c;
    EPID_FpElemStr smu;
    EPID_FpElemStr snu;

} EPID_NRProof;
OE_PACK_END

/*
**==============================================================================
**
** _EPID_Signature
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_Signature
{
    /* Basic signature */
    EPID_BasicSignature sigma0;

    /* Revocation list version number */
    EPID_OctStr32 rl_ver;

    /* number of entries in SigRL */
    EPID_OctStr32 n2;

    /* array of non-revoked proofs (variable length array) */
    OE_ZERO_SIZED_ARRAY EPID_NRProof sigma[0];

} EPID_Signature;
OE_PACK_END

/*
**==============================================================================
**
** _EPID_SigRLEntry
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_SigRLEntry
{
    EPID_G1ElemStr b;
    EPID_G1ElemStr k;
} EPID_SigRLEntry;
OE_PACK_END

/*
**==============================================================================
**
** _EPID_SigRLEntry
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _EPID_SigRL
{
    /* Group identifier */
    EPID_OctStr32 gid[4];

    /* Revocation list number */
    uint8_t rlver[4];

    /* Number of entries */
    uint8_t n2[4];

    /* SigRL entries */
    EPID_SigRLEntry bk[1];
} EPID_SigRL;
OE_PACK_END

OE_EXTERNC_END

#endif /* _OE_EPID_H */
