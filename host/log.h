#ifndef _log_h
#define _log_h

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <openenclave/defs.h>

#if __GNUC__
/* GCC doesn't seem to support Annex K of C11 */
#define fopen_s(fp, fmt, mode)  (((*(fp) = fopen((fmt), (mode))) == NULL) ? errno : 0)
#endif

OE_PRINTF_FORMAT(1,2)
OE_INLINE void Log(const char* fmt, ...)
{
    FILE* os;

    if (!fopen_s(&os, "/tmp/log.txt", "ab"))
    {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(os, fmt, ap);
        va_end(ap);
        fclose(os);
    }
}

OE_INLINE void LogData(
    const void* data,
    size_t size)
{
    FILE* os;

    if (!data || !size)
        return;

    if (!fopen_s(&os, "/tmp/log.bin", "ab"))
    {
        fwrite(data, 1, size, os);
        fclose(os);
    }
}

OE_INLINE void LogHex(
    const void* data_,
    size_t size)
{
    FILE* os;
    const unsigned char* data = (const unsigned char*)data_;

    if (!data || !size)
        return;

    if (!fopen_s(&os, "/tmp/log.txt", "ab"))
    {
        size_t i;

        for (i = 0; i < size; i++)
            fprintf(os, "%02x", data[i]);

        fprintf(os, "\n");
        fclose(os);
    }
}

/* Reverse form of LogHex() */
OE_INLINE void LogHexReverse(
    const unsigned char* data,
    size_t size)
{
    FILE* os;

    if (!data || !size)
        return;

    if (!fopen_s(&os, "/tmp/log.txt", "ab"))
    {
        while (size)
            fprintf(os, "%02x", data[--size]);

        fprintf(os, "\n");
        fclose(os);
    }
}

OE_INLINE unsigned int Checksum(
    const void* data,
    size_t size)
{
    const unsigned char* p = (const unsigned char*)data;
    unsigned int x = 0;

    while (size--)
        x += *p++;

    return x;
}

OE_PACK(
typedef struct _SigstructAttributes
{
    unsigned long long flags;
    unsigned long long xfrm;
}
SigstructAttributes;
)

/* 1808 bytes */
OE_PACK(
typedef struct _Sigstruct
{
    /* (0) must be (06000000E100000000000100H) */
    unsigned char header[12];

    /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
    unsigned int type;

    /* (16) Intel=0x8086, ISV=0x0000 */
    unsigned int vendor;

    /* (20) build date as yyyymmdd */
    unsigned int date;

    /* (24) must be (01010000600000006000000001000000H) */
    unsigned char header2[16];

    /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
    unsigned int swdefined;

    /* (44) Must be 0 */
    unsigned char reserved[84];

    /* (128) Module Public Key (keylength=3072 bits) */
    unsigned char modulus[384];

    /* (512) RSA Exponent = 3 */
    unsigned char exponent[4];

    /* (516) Signature over Header and Body */
    unsigned char signature[384];

    /* (900) The MISCSELECT that must be set */
    unsigned int miscselect;

    /* (904) Mask of MISCSELECT to enforce */
    unsigned int miscmask;

    /* (908) Reserved. Must be 0. */
    unsigned char reserved2[20];

    /* (928) Enclave Attributes that must be set */
    SigstructAttributes attributes;

    /* (944) Mask of Attributes to Enforce */
    SigstructAttributes attributemask;

    /* (960) MRENCLAVE - (32 bytes) */
    unsigned char enclavehash[32];

    /* (992) Must be 0 */
    unsigned char reserved3[32];

    /* (1024) ISV assigned Product ID */
    unsigned short isvprodid;

    /* (1026) ISV assigned SVN */
    unsigned short isvsvn;

    /* (1028) Must be 0 */
    unsigned char reserved4[12];

    /* (1040) Q1 value for RSA Signature Verification */
    unsigned char q1[384];

    /* (1424) Q2 value for RSA Signature Verification */
    unsigned char q2[384];
}
Sigstruct;
)


OE_INLINE void LogSigstruct(const Sigstruct* p)
{
    Log("=== Sigstruct\n");
    Log("header="); LogHex(p->header, sizeof(p->header));
    Log("type=%08x\n", p->type);
    Log("vendor=%08x\n", p->vendor);
    Log("date=%08x\n", p->date);
    Log("header2="); LogHex(p->header2, sizeof(p->header2));
    Log("swdefined=%08x\n", p->swdefined);
    Log("modulus="); LogHex(p->modulus, sizeof(p->modulus));
    Log("exponent="); LogHex(p->exponent, sizeof(p->exponent));
    Log("signature="); LogHex(p->signature, sizeof(p->signature));
    Log("miscselect=%08x\n", p->miscselect);
    Log("miscmask=%08x\n", p->miscmask);
    Log("attributes.flags=%016llx\n", p->attributes.flags);
    Log("attributes.xfrm=%016llx\n", p->attributes.xfrm);
    Log("attributemask.flags=%016llx\n", p->attributemask.flags);
    Log("attributemask.xfrm=%016llx\n", p->attributemask.xfrm);
    Log("enclavehash="); LogHex(p->enclavehash, sizeof(p->enclavehash));
    Log("isvprodid=%04x\n", p->isvprodid);
    Log("isvsvn=%04x\n", p->isvsvn);
    Log("q1="); LogHex(p->q1, sizeof(p->q1));
    Log("q2="); LogHex(p->q2, sizeof(p->q2));
}

#endif /* _log_h */
