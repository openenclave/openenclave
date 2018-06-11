// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>

void __SGX_DumpEinitToken(const SGX_EInitToken* p)
{
    printf("=== SGX_EInitToken:\n");
    printf("valid=%u\n", p->valid);
    printf("attributes.flags=%llx\n", OE_LLX(p->attributes.flags));
    printf("attributes.xfrm=%llx\n", OE_LLX(p->attributes.xfrm));

    printf("mrenclave=");
    OE_HexDump(p->mrenclave, sizeof(p->mrenclave));

    printf("mrsigner=");
    OE_HexDump(p->mrsigner, sizeof(p->mrsigner));

    printf("keyid=");
    OE_HexDump(p->keyid, sizeof(p->keyid));

    printf("isvprodidle=%u\n", p->isvprodidle);

    printf("isvsvnle=%u\n", p->isvsvnle);

    printf("maskedmiscselectle=%u\n", p->maskedmiscselectle);

    printf(
        "maskedattributesle.flags=%llx\n", OE_LLX(p->maskedattributesle.flags));
    printf(
        "maskedattributesle.xfrm=%llx\n", OE_LLX(p->maskedattributesle.xfrm));

    printf("keyid=");
    OE_HexDump(p->keyid, sizeof(p->keyid));

    printf("mac=");
    OE_HexDump(p->mac, sizeof(p->mac));
}

void __SGX_DumpSigStruct(const SGX_SigStruct* p)
{
    printf("=== SGX_Sigstruct\n");
    printf("header=");
    OE_HexDump(p->header, sizeof(p->header));
    printf("type=%08x\n", p->type);
    printf("vendor=%08x\n", p->vendor);
    printf("date=%08x\n", p->date);
    printf("header2=");
    OE_HexDump(p->header2, sizeof(p->header2));
    printf("swdefined=%08x\n", p->swdefined);
    printf("modulus=");
    OE_HexDump(p->modulus, sizeof(p->modulus));
    printf("exponent=");
    OE_HexDump(p->exponent, sizeof(p->exponent));
    printf("signature=");
    OE_HexDump(p->signature, sizeof(p->signature));
    printf("miscselect=%08x\n", p->miscselect);
    printf("miscmask=%08x\n", p->miscmask);
    printf("attributes.flags=%llx\n", OE_LLX(p->attributes.flags));
    printf("attributes.xfrm=%llx\n", OE_LLX(p->attributes.xfrm));
    printf("attributemask.flags=%llx\n", OE_LLX(p->attributemask.flags));
    printf("attributemask.xfrm=%llx\n", OE_LLX(p->attributemask.xfrm));
    printf("enclavehash=");
    OE_HexDump(p->enclavehash, sizeof(p->enclavehash));
    printf("isvprodid=%04x\n", p->isvprodid);
    printf("isvsvn=%04x\n", p->isvsvn);
    printf("q1=");
    OE_HexDump(p->q1, sizeof(p->q1));
    printf("q2=");
    OE_HexDump(p->q2, sizeof(p->q2));
}
