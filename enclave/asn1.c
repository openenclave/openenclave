#include <openenclave/internal/asn1.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/enclavelibc.h>
#include <mbedtls/asn1.h>

typedef struct _oe_asn1_impl_t
{
    const uint8_t* data;
    const uint8_t* end;
    uint8_t* ptr;
}
oe_asn1_impl_t;

OE_INLINE bool _is_valid(const oe_asn1_impl_t* asn1)
{
    if (!asn1 || !asn1->data || !asn1->end || !asn1->ptr)
        return false;

    if (!(asn1->data <= asn1->end))
        return false;

    if (!(asn1->ptr >= asn1->data && asn1->ptr <= asn1->end))
        return false;

    return true;
}

OE_INLINE size_t _remaining(const oe_asn1_impl_t* asn1)
{
    return asn1->end - asn1->ptr;
}

oe_result_t oe_asn1_init(oe_asn1_t* asn1_, const uint8_t* data, size_t size)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (!asn1 || !data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    asn1->data = data;
    asn1->end = data + size;
    asn1->ptr = (uint8_t*)data;

    result = OE_OK;

done:
    return result;
}

const uint8_t* oe_asn1_data(const oe_asn1_t* asn1_)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;

    if (!_is_valid(asn1))
        return NULL;

    return asn1->data;
}

size_t oe_asn1_length(const oe_asn1_t* asn1_)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;

    if (!_is_valid(asn1))
        return 0;

    return asn1->end - asn1->data;
}

size_t oe_asn1_remaining(const oe_asn1_t* asn1_)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;

    if (!_is_valid(asn1))
        return 0;

    return asn1->end - asn1->ptr;
}

const uint8_t* oe_asn1_current(const oe_asn1_t* asn1_)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;

    if (!_is_valid(asn1))
        return NULL;

    return asn1->ptr;
}

oe_result_t oe_asn1_skip(const oe_asn1_t* asn1_, size_t length)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (!_is_valid(asn1))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_remaining(asn1) < length)
        OE_RAISE(OE_FAILURE);

    asn1->ptr += length;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_peek_tag(const oe_asn1_t* asn1_, uint8_t* tag)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (!_is_valid(asn1))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_remaining(asn1) < sizeof(uint8_t))
        OE_RAISE(OE_FAILURE);

    *tag = asn1->ptr[0];

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_tag(oe_asn1_t* asn1_, uint8_t* tag)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    OE_CHECK(oe_asn1_peek_tag(asn1_, tag));

    asn1->ptr += sizeof(uint8_t);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_length(oe_asn1_t* asn1_, size_t* length)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (!_is_valid(asn1))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (mbedtls_asn1_get_len(&asn1->ptr, asn1->end, length) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_integer(oe_asn1_t* asn1_, int* value)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (!_is_valid(asn1))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (mbedtls_asn1_get_int(&asn1->ptr, asn1->end, value) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_sequence(oe_asn1_t* asn1_, oe_asn1_t* sequence_)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_asn1_impl_t* sequence = (oe_asn1_impl_t*)sequence_;
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;
    size_t length;

    if (sequence)
        oe_memset(sequence, 0, sizeof(oe_asn1_t));

    if (!_is_valid(asn1) || !sequence)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get_tag(asn1_, &tag));

    if (tag != (OE_ASN1_TAG_CONSTRUCTED | OE_ASN1_TAG_SEQUENCE))
        OE_RAISE(OE_FAILURE);

    OE_CHECK(oe_asn1_get_length(asn1_, &length));

    OE_CHECK(oe_asn1_init(sequence_, asn1->ptr, length));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get(
    oe_asn1_t* asn1_,
    uint8_t* tag,
    const uint8_t** data,
    size_t* length)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (length)
        *length = 0;

    if (!_is_valid(asn1) || !tag || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get_tag(asn1_, tag));
    OE_CHECK(oe_asn1_get_length(asn1_, length));
    *data = asn1->ptr;
    OE_CHECK(oe_asn1_skip(asn1_, *length));

    result = OE_OK;

done:
    return result;
}


            /* Parse the OID length */
            {
                if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID) != 0)
                    goto done;

                oid.len = len;
                oid.p = p;
                p += oid.len;
            }

            /* Convert OID to a string */
            r = mbedtls_oid_get_numeric_string(
                oidstr.buf, sizeof(oidstr.buf), &oid);
            if (r < 0)
                goto done;

oe_result_t oe_asn1_get_oid(oe_asn1_t* asn1_, int* value)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (!_is_valid(asn1))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (mbedtls_asn1_get_int(&asn1->ptr, asn1->end, value) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}
