#include <openenclave/internal/asn1.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <string.h>

OE_STATIC_ASSERT(V_ASN1_CONSTRUCTED == OE_ASN1_TAG_CONSTRUCTED);
OE_STATIC_ASSERT(V_ASN1_SEQUENCE == OE_ASN1_TAG_SEQUENCE);
OE_STATIC_ASSERT(V_ASN1_INTEGER == OE_ASN1_TAG_INTEGER);
OE_STATIC_ASSERT(V_ASN1_OBJECT == OE_ASN1_TAG_OID);
OE_STATIC_ASSERT(V_ASN1_OCTET_STRING == OE_ASN1_TAG_OCTET_STRING);

OE_INLINE const uint8_t* _end(const oe_asn1_t* asn1)
{
    return asn1->data + asn1->length;
}

OE_INLINE bool _is_valid(const oe_asn1_t* asn1)
{
    if (!asn1 || !asn1->data || !asn1->length || !asn1->ptr)
        return false;

    if (!(asn1->data <= _end(asn1)))
        return false;

    if (!(asn1->ptr >= asn1->data && asn1->ptr <= _end(asn1)))
        return false;

    return true;
}

OE_INLINE size_t _remaining(const oe_asn1_t* asn1)
{
    return _end(asn1) - asn1->ptr;
}

oe_result_t oe_asn1_init(oe_asn1_t* asn1, const uint8_t* data, size_t length)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!asn1 || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    asn1->data = data;
    asn1->length = length;
    asn1->ptr = data;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_peek_tag(const oe_asn1_t* asn1, uint8_t* tag)
{
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
    oe_asn1_t* asn1,
    uint8_t* tag,
    const uint8_t** data,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;

    if (length)
        *length = 0;

    if (!_is_valid(asn1) || !tag || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        long tmp_length = 0;
        int tmp_tag = 0;
        int tmp_class = 0;

        int rc = ASN1_get_object(
            &asn1->ptr, &tmp_length, &tmp_tag, &tmp_class, _remaining(asn1));

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

oe_result_t oe_asn1_get_sequence(oe_asn1_t* asn1, oe_asn1_t* sequence)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;
    const uint8_t* data;
    size_t length;

    if (sequence)
        memset(sequence, 0, sizeof(oe_asn1_t));

    if (!_is_valid(asn1) || !sequence)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get(asn1, &tag, &data, &length));

    if (tag != (OE_ASN1_TAG_CONSTRUCTED | OE_ASN1_TAG_SEQUENCE))
        OE_RAISE(OE_FAILURE);

    OE_CHECK(oe_asn1_init(sequence, data, length));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_integer(oe_asn1_t* asn1, int* value)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;
    const uint8_t* data;
    size_t length;

    if (value)
        *value = 0;

    if (!_is_valid(asn1) || !value)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get(asn1, &tag, &data, &length));

    if (tag != OE_ASN1_TAG_INTEGER)
        OE_RAISE(OE_FAILURE);

    /* Extract the varying-length integer one byte at a time. */
    while (length--)
        *value = (*value << 8) | *data++;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_oid(oe_asn1_t* asn1, oe_oid_string_t* oid)
{
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
    oe_asn1_t* asn1,
    const uint8_t** data,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;

    if (length)
        *length = 0;

    if (!_is_valid(asn1) || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get(asn1, &tag, data, length));

    if (tag != OE_ASN1_TAG_OCTET_STRING)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}
