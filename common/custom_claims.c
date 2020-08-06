// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>

#include "common.h"

/**
 * Serialized buffer will have a header with version and number of
 * claims
 */
typedef struct _oe_custom_claims_header
{
    uint64_t version;
    uint64_t num_claims;
} oe_custom_claims_header_t;

/**
 * Serialized entry for custom claims. Each entry will have the name and value
 * sizes and then the contents of the name and value respectively.
 */
typedef struct _oe_custom_claims_entry
{
    uint64_t name_size;
    uint64_t value_size;
    uint8_t name[];
    // name_size bytes follow.
    // value_size_bytes follow.
} oe_custom_claims_entry_t;

oe_result_t oe_free_serialized_custom_claims(uint8_t* custom_claims_buffer)
{
    oe_free(custom_claims_buffer);
    return OE_OK;
}

static void _free_claim(oe_claim_t* claim)
{
    oe_free(claim->name);
    oe_free(claim->value);
}

oe_result_t oe_free_custom_claims(oe_claim_t* claims, size_t claims_length)
{
    if (!claims)
        return OE_OK;

    for (size_t i = 0; i < claims_length; i++)
        _free_claim(&claims[i]);
    oe_free(claims);
    return OE_OK;
}

static oe_result_t _add_claim(
    oe_claim_t* claim,
    const uint8_t* name,
    size_t name_size, // Must cover the '\0' at end of string
    const void* value,
    size_t value_size)
{
    if (*(name + name_size - 1) != '\0')
        return OE_CONSTRAINT_FAILED;

    claim->name = (char*)oe_malloc(name_size);
    if (claim->name == NULL)
        return OE_OUT_OF_MEMORY;
    oe_memcpy_s(claim->name, name_size, name, name_size);

    claim->value = (uint8_t*)oe_malloc(value_size);
    if (claim->value == NULL)
    {
        oe_free(claim->name);
        claim->name = NULL;
        return OE_OUT_OF_MEMORY;
    }
    oe_memcpy_s(claim->value, value_size, value, value_size);
    claim->value_size = value_size;

    return OE_OK;
}

static oe_result_t _fill_array_with_custom_claims(
    const uint8_t* claims_buffer,
    size_t claims_buffer_size,
    oe_claim_t* claims)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_custom_claims_header_t* header =
        (oe_custom_claims_header_t*)claims_buffer;
    size_t claims_index = 0;

    if (claims_buffer_size < sizeof(*header))
    {
        OE_RAISE(OE_CONSTRAINT_FAILED);
    }

    claims_buffer += sizeof(*header);
    claims_buffer_size -= sizeof(*header);
    for (uint64_t i = 0; i < header->num_claims; i++)
    {
        oe_custom_claims_entry_t* entry =
            (oe_custom_claims_entry_t*)claims_buffer;
        uint64_t size = 0;

        // Sanity check sizes.
        if (claims_buffer_size < sizeof(*entry))
            OE_RAISE(OE_CONSTRAINT_FAILED);

        OE_CHECK(oe_safe_add_u64(sizeof(*entry), entry->name_size, &size));
        OE_CHECK(oe_safe_add_u64(size, entry->value_size, &size));

        if (claims_buffer_size < size)
            OE_RAISE(OE_CONSTRAINT_FAILED);

        // Add the claim.
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            entry->name,
            entry->name_size,
            entry->name + entry->name_size,
            entry->value_size));

        OE_CHECK(
            oe_safe_sub_u64(claims_buffer_size, size, &claims_buffer_size));
        claims_buffer += size;
    }

    result = OE_OK;

done:
    if (result != OE_OK)
    {
        for (size_t i = 0; i < claims_index; i++)
            _free_claim(&claims[i]);
    }
    return result;
}

oe_result_t oe_deserialize_custom_claims(
    const uint8_t* claims_buffer,
    size_t claims_buffer_size,
    oe_claim_t** claims_out,
    size_t* claims_length_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_custom_claims_header_t* claims_header = NULL;
    oe_claim_t* claims = NULL;
    uint64_t claims_length = 0;
    uint64_t claims_size = 0;

    if (claims_buffer_size < sizeof(oe_custom_claims_header_t))
    {
        OE_RAISE(OE_CONSTRAINT_FAILED);
    }

    claims_header = (oe_custom_claims_header_t*)(claims_buffer);

    if (claims_header == NULL)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    if (claims_header->version != OE_CUSTOM_CLAIMS_VERSION)
    {
        OE_RAISE(OE_CONSTRAINT_FAILED);
    }

    claims_length = claims_header->num_claims;

    OE_CHECK(oe_safe_mul_u64(claims_length, sizeof(oe_claim_t), &claims_size));

    claims = (oe_claim_t*)oe_malloc(claims_size);
    if (claims == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(_fill_array_with_custom_claims(
        claims_buffer, claims_buffer_size, claims));

    *claims_out = claims;
    *claims_length_out = claims_header->num_claims;
    claims = NULL;
    result = OE_OK;

done:
    if (claims)
        oe_free_custom_claims(claims, claims_length);
    return result;
}

static oe_result_t _get_claims_size(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!custom_claims)
        return OE_OK;

    OE_CHECK(oe_safe_add_u64(*size, sizeof(oe_custom_claims_header_t), size));

    for (size_t i = 0; i < custom_claims_length; i++)
    {
        OE_CHECK(
            oe_safe_add_u64(*size, sizeof(oe_custom_claims_entry_t), size));
        OE_CHECK(
            oe_safe_add_u64(*size, oe_strlen(custom_claims[i].name) + 1, size));
        OE_CHECK(oe_safe_add_u64(*size, custom_claims[i].value_size, size));
    }
    result = OE_OK;
done:
    return result;
}

static void _fill_buffer_with_custom_claims(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t* claims)
{
    // Custom claims structure would be:
    //  - oe_custom_claims_header_t
    //  - N claim entries of oe_sgx_custom_claims_entry_t
    // claims buffer is previously allocated with appropriate size,
    // copy corresponding values
    oe_custom_claims_header_t* header = (oe_custom_claims_header_t*)claims;
    header->version = OE_CUSTOM_CLAIMS_VERSION;
    header->num_claims = custom_claims ? custom_claims_length : 0;
    claims += sizeof(oe_custom_claims_header_t);

    if (!custom_claims)
        return;

    for (size_t i = 0; i < custom_claims_length; i++)
    {
        oe_custom_claims_entry_t* entry = (oe_custom_claims_entry_t*)claims;
        entry->name_size = oe_strlen(custom_claims[i].name) + 1;
        entry->value_size = custom_claims[i].value_size;
        oe_memcpy_s(
            entry->name,
            entry->name_size,
            custom_claims[i].name,
            entry->name_size);
        oe_memcpy_s(
            entry->name + entry->name_size,
            entry->value_size,
            custom_claims[i].value,
            entry->value_size);
        // move to next claim
        claims += sizeof(*entry) + entry->name_size + entry->value_size;
    }
}

oe_result_t oe_serialize_custom_claims(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t** claims_out,
    size_t* claims_size_out)
{
    uint8_t* claims = NULL;
    size_t claims_size = 0;
    oe_result_t result = OE_UNEXPECTED;

    // Get claims size.
    OE_CHECK(
        _get_claims_size(custom_claims, custom_claims_length, &claims_size));

    // Allocate memory and set the claims.
    claims = (uint8_t*)oe_malloc(claims_size);
    if (claims == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);
    _fill_buffer_with_custom_claims(
        custom_claims, custom_claims_length, claims);

    *claims_out = claims;
    *claims_size_out = claims_size;
    claims = NULL;
    result = OE_OK;

done:
    if (claims != NULL)
        oe_free(claims);
    return result;
}
