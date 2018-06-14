// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/utils.h>
#include <stdio.h>

void __sgx_dump_einit_token(const sgx_einittoken_t* p)
{
    printf("=== sgx_einittoken_t:\n");
    printf("valid=%u\n", p->valid);
    printf("attributes.flags=" OE_I64X_F "\n", p->attributes.flags);
    printf("attributes.xfrm=" OE_I64X_F "\n", p->attributes.xfrm);

    printf("mrenclave=");
    oe_hex_dump(p->mrenclave, sizeof(p->mrenclave));

    printf("mrsigner=");
    oe_hex_dump(p->mrsigner, sizeof(p->mrsigner));

    printf("keyid=");
    oe_hex_dump(p->keyid, sizeof(p->keyid));

    printf("isvprodidle=%u\n", p->isvprodidle);

    printf("isvsvnle=%u\n", p->isvsvnle);

    printf("maskedmiscselectle=%u\n", p->maskedmiscselectle);

    printf(
        "maskedattributesle.flags=" OE_I64X_F "\n",
        p->maskedattributesle.flags);
    printf(
        "maskedattributesle.xfrm=" OE_I64X_F "\n", p->maskedattributesle.xfrm);

    printf("keyid=");
    oe_hex_dump(p->keyid, sizeof(p->keyid));

    printf("mac=");
    oe_hex_dump(p->mac, sizeof(p->mac));
}

void __sgx_dump_sigstruct(const sgx_sigstruct_t* p)
{
    printf("=== sgx_sigstruct\n");
    printf("header=");
    oe_hex_dump(p->header, sizeof(p->header));
    printf("type=%08x\n", p->type);
    printf("vendor=%08x\n", p->vendor);
    printf("date=%08x\n", p->date);
    printf("header2=");
    oe_hex_dump(p->header2, sizeof(p->header2));
    printf("swdefined=%08x\n", p->swdefined);
    printf("modulus=");
    oe_hex_dump(p->modulus, sizeof(p->modulus));
    printf("exponent=");
    oe_hex_dump(p->exponent, sizeof(p->exponent));
    printf("signature=");
    oe_hex_dump(p->signature, sizeof(p->signature));
    printf("miscselect=%08x\n", p->miscselect);
    printf("miscmask=%08x\n", p->miscmask);
    printf("attributes.flags=" OE_I64X_F "\n", p->attributes.flags);
    printf("attributes.xfrm=" OE_I64X_F "\n", p->attributes.xfrm);
    printf("attributemask.flags=" OE_I64X_F "\n", p->attributemask.flags);
    printf("attributemask.xfrm=" OE_I64X_F "\n", p->attributemask.xfrm);
    printf("enclavehash=");
    oe_hex_dump(p->enclavehash, sizeof(p->enclavehash));
    printf("isvprodid=%04x\n", p->isvprodid);
    printf("isvsvn=%04x\n", p->isvsvn);
    printf("q1=");
    oe_hex_dump(p->q1, sizeof(p->q1));
    printf("q2=");
    oe_hex_dump(p->q2, sizeof(p->q2));
}
