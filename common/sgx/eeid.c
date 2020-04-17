// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/bits/eeid.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/types.h>
#include <openenclave/internal/utils.h>

#include "../../host/sgx/sgxmeasure.h"

static oe_result_t serialize_elem(
    const char* name,
    char** p,
    size_t* r,
    const uint8_t* e,
    size_t e_sz)
{
    size_t name_sz = strlen(name);

    if (*r < 2 * e_sz + 1 + name_sz + 1)
        return OE_BUFFER_TOO_SMALL;

    snprintf(*p, *r, "%s=", name);
    *p += name_sz + 1;
    *r -= name_sz + 1;

    oe_hex_string(*p, *r, e, e_sz);
    *p += 2 * e_sz;
    **p = '\n';
    *p += 1;
    *r -= 2 * e_sz + 1;

    return OE_OK;
}

static oe_result_t deserialize_elem(
    const char** p,
    size_t* r,
    uint8_t* e,
    size_t e_sz)
{
    // Skip name
    while (**p != ' ')
    {
        *p += 1;
        *r -= 1;
    }
    *p += 1;
    *r -= 1;

    if (*r < 2 * e_sz + 2)
        return OE_OUT_OF_BOUNDS;

    for (size_t i = 0; i < e_sz; i++)
    {
        unsigned digit;
        if (sscanf(*p, "%02x", &digit) != 1)
            return OE_INVALID_PARAMETER;
        e[i] = (uint8_t)digit;
        *p += 2;
        *r -= 2;
    }

    if (**p != '\n')
        return OE_INVALID_PARAMETER;

    *p += 1;
    *r -= 1;

    return OE_OK;
}

oe_result_t oe_serialize_eeid(const oe_eeid_t* eeid, char* buf, size_t buf_size)
{
    oe_result_t result;

    if (!eeid || !buf || !buf_size)
        return OE_INVALID_PARAMETER;

    char** p = &buf;
    size_t r = buf_size;

    OE_CHECK(serialize_elem(
        "H", p, &r, (uint8_t*)eeid->hash_state.H, sizeof(eeid->hash_state.H)));
    OE_CHECK(serialize_elem(
        "N", p, &r, (uint8_t*)eeid->hash_state.N, sizeof(eeid->hash_state.N)));
    OE_CHECK(serialize_elem(
        "signature_size",
        p,
        &r,
        (uint8_t*)&eeid->signature_size,
        sizeof(eeid->signature_size)));
    OE_CHECK(serialize_elem(
        "signature", p, &r, eeid->signature, eeid->signature_size));
    OE_CHECK(serialize_elem(
        "settings",
        p,
        &r,
        (uint8_t*)&eeid->size_settings,
        sizeof(eeid->size_settings)));
    OE_CHECK(serialize_elem(
        "data_size",
        p,
        &r,
        (uint8_t*)&eeid->data_size,
        sizeof(eeid->data_size)));
    OE_CHECK(serialize_elem(
        "vaddr", p, &r, (uint8_t*)&eeid->vaddr, sizeof(eeid->vaddr)));
    OE_CHECK(serialize_elem(
        "entry_point",
        p,
        &r,
        (uint8_t*)&eeid->entry_point,
        sizeof(eeid->entry_point)));
    OE_CHECK(
        serialize_elem("data", p, &r, (uint8_t*)eeid->data, eeid->data_size));

    **p = '\0';

done:
    return OE_OK;
}

oe_result_t oe_deserialize_eeid(
    const char* buf,
    size_t buf_size,
    oe_eeid_t* eeid)
{
    oe_result_t result;

    if (!buf || !buf_size || !eeid)
        return OE_INVALID_PARAMETER;

    const char** p = &buf;
    size_t r = buf_size;

    memset(eeid, 0, sizeof(oe_eeid_t));

    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)eeid->hash_state.H, sizeof(eeid->hash_state.H)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)eeid->hash_state.N, sizeof(eeid->hash_state.N)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)&eeid->signature_size, sizeof(eeid->signature_size)));
    OE_CHECK(deserialize_elem(p, &r, eeid->signature, eeid->signature_size));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)&eeid->size_settings, sizeof(eeid->size_settings)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)&eeid->data_size, sizeof(eeid->data_size)));
    OE_CHECK(
        deserialize_elem(p, &r, (uint8_t*)&eeid->vaddr, sizeof(eeid->vaddr)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)&eeid->entry_point, sizeof(eeid->entry_point)));
    OE_CHECK(deserialize_elem(p, &r, (uint8_t*)eeid->data, eeid->data_size));

done:
    return OE_OK;
}

oe_result_t oe_replay_eeid_pages(
    const oe_eeid_t* eeid,
    struct _OE_SHA256* cpt_mrenclave)
{
    oe_result_t result;
    oe_sha256_context_t hctx;
    oe_sha256_restore(&hctx, eeid->hash_state.H, eeid->hash_state.N);
    uint64_t base = 0x0ab0c0d0e0f;

    oe_page_t blank_pg, stack_pg, tcs_pg;
    memset(&blank_pg, 0, sizeof(blank_pg));
    memset(&stack_pg, 0xcc, sizeof(stack_pg));

#define ADD_PAGE(PG, T)                                      \
    {                                                        \
        OE_CHECK(oe_sgx_measure_load_enclave_data(           \
            &hctx,                                           \
            base,                                            \
            base + vaddr,                                    \
            (uint64_t)&PG,                                   \
            SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W, \
            T));                                             \
        vaddr += OE_PAGE_SIZE;                               \
    }

    uint64_t vaddr = eeid->vaddr;
    for (size_t i = 0; i < eeid->size_settings.num_heap_pages; i++)
        ADD_PAGE(blank_pg, false);

    for (size_t i = 0; i < eeid->size_settings.num_tcs; i++)
    {
        vaddr += OE_PAGE_SIZE; /* guard page */

        for (size_t i = 0; i < eeid->size_settings.num_stack_pages; i++)
            ADD_PAGE(stack_pg, true);

        vaddr += OE_PAGE_SIZE; /* guard page */

        sgx_tcs_t* tcs;
        memset(&tcs_pg, 0, sizeof(tcs_pg));
        tcs = (sgx_tcs_t*)&tcs_pg;
        tcs->flags = 0;
        tcs->ossa = vaddr + OE_PAGE_SIZE;
        tcs->cssa = 0;
        tcs->nssa = 2;
        tcs->oentry = eeid->entry_point;
        tcs->fsbase = vaddr + (5 * OE_PAGE_SIZE);
        tcs->gsbase = tcs->fsbase;
        tcs->fslimit = 0xFFFFFFFF;
        tcs->gslimit = 0xFFFFFFFF;

        OE_CHECK(oe_sgx_measure_load_enclave_data(
            &hctx,
            base,
            base + vaddr,
            (uint64_t)&tcs_pg,
            SGX_SECINFO_TCS,
            true));

        vaddr += OE_PAGE_SIZE;

        for (size_t i = 0; i < 2; i++)
            ADD_PAGE(blank_pg, true);
        vaddr += OE_PAGE_SIZE; // guard
        for (size_t i = 0; i < 2; i++)
            ADD_PAGE(blank_pg, true);
    }

    size_t eeid_sz = sizeof(oe_eeid_t) + eeid->data_size;
    size_t num_pages = oe_round_up_to_page_size(eeid_sz) / OE_PAGE_SIZE;
    oe_page_t* pages = (oe_page_t*)eeid;
    for (size_t i = 0; i < num_pages; i++)
    {
        uint8_t* page = (uint8_t*)&pages[i];

        if (i == num_pages - 1 && eeid_sz % OE_PAGE_SIZE != 0)
        {
            uint8_t* npage = calloc(1, OE_PAGE_SIZE);
            memcpy(npage, page, eeid_sz % OE_PAGE_SIZE);
            page = npage;
        }

        OE_CHECK(oe_sgx_measure_load_enclave_data(
            &hctx,
            base,
            base + vaddr,
            (uint64_t)page,
            SGX_SECINFO_REG | SGX_SECINFO_R,
            true));

        if (i == num_pages - 1 && eeid_sz % OE_PAGE_SIZE != 0)
            free(page);

        vaddr += OE_PAGE_SIZE;
    }

    oe_sha256_final(&hctx, cpt_mrenclave);

done:
    return OE_OK;
}