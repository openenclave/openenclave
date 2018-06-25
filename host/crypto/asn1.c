#include <openenclave/internal/asn1.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/enclavelibc.h>
#include <openssl/asn1.h>
#include <string.h>
#include <openssl/pem.h>

OE_STATIC_ASSERT(V_ASN1_CONSTRUCTED == OE_ASN1_TAG_CONSTRUCTED);
OE_STATIC_ASSERT(V_ASN1_SEQUENCE == OE_ASN1_TAG_SEQUENCE);
OE_STATIC_ASSERT(V_ASN1_INTEGER == OE_ASN1_TAG_INTEGER);
OE_STATIC_ASSERT(V_ASN1_OBJECT == OE_ASN1_TAG_OID);
OE_STATIC_ASSERT(V_ASN1_OCTET_STRING == OE_ASN1_TAG_OCTET_STRING);

typedef struct _oe_asn1_impl_t
{
    const uint8_t* data;
    const uint8_t* end;
    const uint8_t* ptr;
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

oe_result_t oe_asn1_init(oe_asn1_t* asn1_, const uint8_t* data, size_t length)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;

    if (!asn1 || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    asn1->data = data;
    asn1->end = data + length;
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

size_t oe_asn1_offset(const oe_asn1_t* asn1_)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;

    if (!_is_valid(asn1))
        return 0;

    return asn1->ptr - asn1->data;
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

    {
        long tmp_length = 0;
        int tmp_tag = 0;
        int tmp_class = 0;

        int rc = ASN1_get_object(&asn1->ptr, &tmp_length, &tmp_tag, 
            &tmp_class, _remaining(asn1));

        if (rc != V_ASN1_CONSTRUCTED && rc != 0)
            OE_RAISE(OE_FAILURE);

        *tag = rc | tmp_tag;
        *data = asn1->ptr;
        *length = (size_t)tmp_length;

        asn1->ptr += *length;
    }

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
    const uint8_t* data;
    size_t length;

    if (sequence)
        memset(sequence, 0, sizeof(oe_asn1_t));

    if (!_is_valid(asn1) || !sequence)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get(asn1_, &tag, &data, &length));

    if (tag != (OE_ASN1_TAG_CONSTRUCTED | OE_ASN1_TAG_SEQUENCE))
        OE_RAISE(OE_FAILURE);

    OE_CHECK(oe_asn1_init(sequence_, data, length));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_integer(oe_asn1_t* asn1_, int* value)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;
    const uint8_t* data;
    size_t length;

    if (value)
        *value = 0;

    if (!_is_valid(asn1) || !value)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get(asn1_, &tag, &data, &length));

    if (tag != OE_ASN1_TAG_INTEGER)
        OE_RAISE(OE_FAILURE);

    /* Extract the varying-length integer one byte at a time. */
    while (length--)
        *value = (*value << 8) | *data++;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_oid(oe_asn1_t* asn1_, oe_oid_string_t* oid)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;
    ASN1_OBJECT* obj = NULL;

    if (oid)
        memset(oid, 0, sizeof(oe_oid_string_t));

    if (!_is_valid(asn1) || !oid)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the OID and covert it to string */
    {
        const unsigned char* ptr = asn1->ptr;

        /* Convert OID to an ASN1 object */
        if (!(obj = d2i_ASN1_OBJECT(&obj, &ptr, _remaining(asn1))))
            OE_RAISE(OE_FAILURE);

        /* Convert OID to string format */
        if (!OBJ_obj2txt(oid->buf, sizeof(oe_oid_string_t), obj, 1))
            OE_RAISE(OE_FAILURE);

        asn1->ptr = ptr;
    }

    result = OE_OK;

done:

    if (obj)
        ASN1_OBJECT_free(obj);

    return result;
}

oe_result_t oe_asn1_get_octet_string(
    oe_asn1_t* asn1_, 
    const uint8_t** data,
    size_t* length)
{
    oe_asn1_impl_t* asn1 = (oe_asn1_impl_t*)asn1_;
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;

    if (length)
        *length = 0;

    if (!_is_valid(asn1) || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get(asn1_, &tag, data, length));

    if (tag != OE_ASN1_TAG_OCTET_STRING)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}
