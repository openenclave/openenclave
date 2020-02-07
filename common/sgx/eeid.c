// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>

#include <openenclave/bits/eeid.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>

static oe_result_t serialize_elem(
    char** p,
    size_t* r,
    const uint8_t* e,
    size_t e_sz)
{
    if (*r < 2 * e_sz + 1)
        return OE_BUFFER_TOO_SMALL;

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
    size_t eeid_sz = sizeof(oe_eeid_t) + eeid->data_size;
    size_t str_sz = 2 * eeid_sz + 1;

    if (str_sz >= buf_size)
        return OE_BUFFER_TOO_SMALL;

    char** p = &buf;
    size_t r = buf_size;

    OE_CHECK(serialize_elem(
        p, &r, (uint8_t*)eeid->hash_state_H, sizeof(eeid->hash_state_H)));
    OE_CHECK(serialize_elem(
        p, &r, (uint8_t*)eeid->hash_state_N, sizeof(eeid->hash_state_N)));
    OE_CHECK(serialize_elem(
        p, &r, (uint8_t*)eeid->sigstruct, sizeof(eeid->sigstruct)));
    OE_CHECK(serialize_elem(
        p, &r, (uint8_t*)&eeid->size_settings, sizeof(eeid->size_settings)));
    OE_CHECK(serialize_elem(
        p, &r, (uint8_t*)&eeid->data_size, sizeof(eeid->data_size)));
    OE_CHECK(serialize_elem(
        p, &r, (uint8_t*)&eeid->data_vaddr, sizeof(eeid->data_vaddr)));
    OE_CHECK(serialize_elem(p, &r, (uint8_t*)eeid->data, eeid->data_size));

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
    const char** p = &buf;
    size_t r = buf_size;

    memset(eeid, 0, sizeof(oe_eeid_t));

    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)eeid->hash_state_H, sizeof(eeid->hash_state_H)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)eeid->hash_state_N, sizeof(eeid->hash_state_N)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)eeid->sigstruct, sizeof(eeid->sigstruct)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)&eeid->size_settings, sizeof(eeid->size_settings)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)&eeid->data_size, sizeof(eeid->data_size)));
    OE_CHECK(deserialize_elem(
        p, &r, (uint8_t*)&eeid->data_vaddr, sizeof(eeid->data_vaddr)));
    OE_CHECK(deserialize_elem(p, &r, (uint8_t*)eeid->data, eeid->data_size));

done:
    return OE_OK;
}