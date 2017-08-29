#include <stdio.h>
#include <__openenclave/sgxtypes.h>
#include <__openenclave/utils.h>

void __SGX_DumpEinitToken(
    const SGX_EInitToken* p)
{
    printf("=== SGX_EInitToken:\n");
    printf("valid=%u\n", p->valid);
    printf("attributes.flags=%016lx\n", p->attributes.flags);
    printf("attributes.xfrm=%016lx\n", p->attributes.xfrm);

    printf("mrenclave=");
    __OE_HexDump(p->mrenclave, sizeof(p->mrenclave));

    printf("mrsigner=");
    __OE_HexDump(p->mrsigner, sizeof(p->mrsigner));

    printf("keyid=");
    __OE_HexDump(p->keyid, sizeof(p->keyid));

    printf("isvprodidle=%u\n", p->isvprodidle);

    printf("isvsvnle=%u\n", p->isvsvnle);

    printf("maskedmiscselectle=%u\n", p->maskedmiscselectle);

    printf("maskedattributesle.flags=%016lx\n", p->maskedattributesle.flags);
    printf("maskedattributesle.xfrm=%016lx\n", p->maskedattributesle.xfrm);

    printf("keyid=");
    __OE_HexDump(p->keyid, sizeof(p->keyid));

    printf("mac=");
    __OE_HexDump(p->mac, sizeof(p->mac));
}

void __SGX_DumpSigStruct(
    const SGX_SigStruct* p)
{
    printf("=== SGX_Sigstruct\n");
    printf("header="); __OE_HexDump(p->header, sizeof(p->header));
    printf("type=%08x\n", p->type);
    printf("vendor=%08x\n", p->vendor);
    printf("date=%08x\n", p->date);
    printf("header2="); __OE_HexDump(p->header2, sizeof(p->header2));
    printf("swdefined=%08x\n", p->swdefined);
    printf("modulus="); __OE_HexDump(p->modulus, sizeof(p->modulus));
    printf("exponent="); __OE_HexDump(p->exponent, sizeof(p->exponent));
    printf("signature="); __OE_HexDump(p->signature, sizeof(p->signature));
    printf("miscselect=%08x\n", p->miscselect);
    printf("miscmask=%08x\n", p->miscmask);
    printf("attributes.flags=%016lx\n", p->attributes.flags);
    printf("attributes.xfrm=%016lx\n", p->attributes.xfrm);
    printf("attributemask.flags=%016lx\n", p->attributemask.flags);
    printf("attributemask.xfrm=%016lx\n", p->attributemask.xfrm);
    printf("enclavehash=");
    __OE_HexDump(p->enclavehash, sizeof(p->enclavehash));
    printf("isvprodid=%04x\n", p->isvprodid);
    printf("isvsvn=%04x\n", p->isvsvn);
    printf("q1="); __OE_HexDump(p->q1, sizeof(p->q1));
    printf("q2="); __OE_HexDump(p->q2, sizeof(p->q2));
}
