// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/types.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>

void __sgx_dump_einittoken(const sgx_einittoken_t* p)
{
    printf("=== sgx_einittoken_t:\n");
    printf("valid=%u\n", p->valid);
    printf("attributes.flags=%llx\n", OE_LLX(p->attributes.flags));
    printf("attributes.xfrm=%llx\n", OE_LLX(p->attributes.xfrm));

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
        "maskedattributesle.flags=%llx\n", OE_LLX(p->maskedattributesle.flags));
    printf(
        "maskedattributesle.xfrm=%llx\n", OE_LLX(p->maskedattributesle.xfrm));

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
    printf("attributes.flags=%llx\n", OE_LLX(p->attributes.flags));
    printf("attributes.xfrm=%llx\n", OE_LLX(p->attributes.xfrm));
    printf("attributemask.flags=%llx\n", OE_LLX(p->attributemask.flags));
    printf("attributemask.xfrm=%llx\n", OE_LLX(p->attributemask.xfrm));
    printf("enclavehash=");
    oe_hex_dump(p->enclavehash, sizeof(p->enclavehash));
    printf("isvprodid=%04x\n", p->isvprodid);
    printf("isvsvn=%04x\n", p->isvsvn);
    printf("q1=");
    oe_hex_dump(p->q1, sizeof(p->q1));
    printf("q2=");
    oe_hex_dump(p->q2, sizeof(p->q2));
}
