// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/crypto/ec.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/trace.h>
#include "../common.h"

#define SGX_EXTENSION_OID_STR "1.2.840.113741.1.13.1"
#define SGX_EXTENSION_OID "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01"

#define PPID_OID SGX_EXTENSION_OID "\x01"

#define TCB_OID SGX_EXTENSION_OID "\x02"

static const char* _tcb_comp_svn_oids[16] = {
    TCB_OID "\x01",
    TCB_OID "\x02",
    TCB_OID "\x03",
    TCB_OID "\x04",
    TCB_OID "\x05",
    TCB_OID "\x06",
    TCB_OID "\x07",
    TCB_OID "\x08",
    TCB_OID "\x09",
    TCB_OID "\x0a",
    TCB_OID "\x0b",
    TCB_OID "\x0c",
    TCB_OID "\x0d",
    TCB_OID "\x0e",
    TCB_OID "\x0f",
    TCB_OID "\x10",
};

#define TCB_PCESVN_OID TCB_OID "\x11"
#define TCB_CPUSVN_OID TCB_OID "\x12"

#define PCEID_OID SGX_EXTENSION_OID "\x03"
#define FMSPC_OID SGX_EXTENSION_OID "\x04"
#define SGX_TYPE_OID SGX_EXTENSION_OID "\x05"
#define OPT_PLATFORM_INSTANCE_ID_OID SGX_EXTENSION_OID "\x06"
#define OPT_CONFIGURATION_OID SGX_EXTENSION_OID "\x07"
#define OPT_DYNAMIC_PLATFORM_OID OPT_CONFIGURATION_OID "\x01"
#define OPT_CACHED_KEYS_OID OPT_CONFIGURATION_OID "\x02"
#define OPT_SMT_ENABLED_OID OPT_CONFIGURATION_OID "\x03"

// ASN1 tag fields are single-byte values consisting of the following
// bit-fields:
//    class : bits 6-7
//    is-structured : bit 5
//    tag  : bits 0-4
// The following enumerations are exact byte values of various entities expected
// in SGX extensions, combining the class, is-structured, and tag values.

#define SGX_BOOLEAN_TAG (0x01)
#define SGX_INTEGER_TAG (0x02)
#define SGX_OCTET_STRING_TAG (0x04)
#define SGX_OBJECT_ID_TAG (0x06)
#define SGX_ENUMERATION_TAG (0x0a)
#define SGX_SEQUENCE_TAG (0x30)

OE_STATIC_ASSERT(
    OE_COUNTOF(((ParsedExtensionInfo*)0)->comp_svn) ==
    OE_COUNTOF(_tcb_comp_svn_oids));

/**
 * Read length from the current location in ASN1 stream.
 * Length has 3 encodings described below:
 * Assume p is the current location in ASN1 stream.
 *
 * 1) If *p < 0x80, then *p is the length.
 * 2) If *p > 0x80, then *p-0x80 is the number of bytes that make up the length.
 * 3) If *p == 0x80, then the data is variable length and is terminated by two
 * zeros. We don't support this since Intel extensions are not variable length.
 */
static oe_result_t _read_asn1_length(
    uint8_t** itr,
    uint8_t* end,
    size_t* length)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* p = NULL;
    uint8_t bytes = 0;

    if (itr == NULL || *itr == NULL || end == NULL || length == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    p = *itr;
    *length = 0;

    if (p < end)
    {
        if (*p < 0x80)
        {
            // Length is *p.
            *length = *p++;
            *itr = p;
        }
        else if (*p > 0x80)
        {
            bytes = (uint8_t)(*p++ - 0x80);
            while (bytes > 0 && p < end)
            {
                *length = (*length << 8) | *p;
                ++p;
                --bytes;
            }
            // Assert that all the length bytes were read.
            if (bytes == 0)
            {
                *itr = p;
            }
        }
    }

    // Ensure that the read length is valid.
    if (*length && (*itr + *length <= end))
        result = OE_OK;

done:

    return result;
}

/**
 * Check whether an oid is equal to the given byte value string.
 */
static int8_t _oid_equal(
    uint8_t* oid,
    uint8_t* end,
    size_t oid_length,
    const char* expected_oid)
{
    size_t expected_length = oe_strlen(expected_oid);
    return (oid_length == expected_length) && (oid + oid_length < end) &&
           (memcmp(oid, expected_oid, oid_length) == 0);
}

/**
 * Each individual extension is encoded as an ASN1 sequence object
 * that consists of two objects: oid object, data object.
 * extension = (SGX_SEQUENCE_TAG sequence_length
 *                 (SGX_OBJECT_ID_TAG oid_length oid_bytes)
 *                 (data_tag data_length data_bytes)
 *              )
 */
static oe_result_t _read_extension(
    uint8_t** itr,
    uint8_t* end,
    const char* expected_oid,
    uint8_t data_tag,
    uint8_t** data,
    size_t* data_length)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* p = NULL;
    size_t length = 0;
    size_t oid_length = 0;
    uint8_t* object_end = NULL;

    if (itr == NULL || *itr == NULL || end == NULL || expected_oid == NULL ||
        data == NULL || data_length == NULL)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    p = *itr;
    if (p >= end)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    if (*p++ == SGX_SEQUENCE_TAG && p < end)
    {
        OE_CHECK(_read_asn1_length(&p, end, &length));
        if (p + length <= end && length > 0)
        {
            // Record the end of current sequence object.
            object_end = p + length;
            if (*p++ == SGX_OBJECT_ID_TAG && p < end)
            {
                OE_CHECK(_read_asn1_length(&p, end, &oid_length));
                if (!_oid_equal(p, end, oid_length, expected_oid))
                    OE_RAISE(OE_FAILURE);
                p += oid_length;
                if (p < end && *p++ == data_tag)
                {
                    OE_CHECK(_read_asn1_length(&p, end, data_length));
                    if (p + *data_length == object_end)
                    {
                        *data = p;
                        *itr = object_end;
                        result = OE_OK;
                    }
                }
            }
        }
    }
done:
    return result;
}

static void _trace_hex_dump(const char* tag, const uint8_t* data, size_t size)
{
    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
    {
        OE_TRACE_INFO("%s = ", tag);
        oe_hex_dump(data, size);
    }
}

/**
 * Read an extension with given oid and data of type octet string.
 */
static oe_result_t _read_octet_extension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint8_t* buffer,
    size_t length)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t data_length = 0;

    OE_CHECK(_read_extension(
        itr, end, oid, SGX_OCTET_STRING_TAG, &data, &data_length));
    if (data_length != length)
        OE_RAISE(OE_FAILURE);

    OE_CHECK(oe_memcpy_s(buffer, length, data, data_length));
    _trace_hex_dump(tag, buffer, data_length);
    result = OE_OK;
done:
    return result;
}

/**
 * Read an Integer extension with given oid and check that the value fits in
 * the specified number of bytes.
 */
static oe_result_t _read_integer_extension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    size_t num_bytes,
    uint64_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t data_length = 0;

    OE_CHECK(
        _read_extension(itr, end, oid, SGX_INTEGER_TAG, &data, &data_length));

    *value = 0;
    for (size_t i = 0; i < data_length; ++i)
    {
        *value = (*value << 8) | (data[i]);
    }

    // If the leftmost bit of the integer is 1, then it is prefixed with a zero
    // byte to indicate that it is a positive number, rather than a negative
    // number. Negative numbers in two's complement form have the leftmost bit
    // set. Thus, data_length can be num_bytes + 1, in which case the first byte
    // must be zero.
    if (data_length == num_bytes + 1)
    {
        if (data[0] != 0)
            OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);
    }
    else
    {
        if (data_length > num_bytes)
            OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);
    }

    OE_TRACE_INFO("%s = %lu\n", tag, *value);
    result = OE_OK;

done:
    return result;
}

/**
 * Read an Integer extension with given oid and check that the value fits in a
 * byte.
 */
static oe_result_t _read_integer_extension_as_uint8(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint8_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint64_t value64 = 0;

    OE_CHECK(
        _read_integer_extension(tag, oid, itr, end, sizeof(uint8_t), &value64));

    *value = (uint8_t)value64;
    result = OE_OK;

done:
    return result;
}

/**
 * Read an Integer extension with given oid and check that the value fits in a
 * uint16_t.
 */
static oe_result_t _read_integer_extension_as_uint16(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint16_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint64_t value64 = 0;

    OE_CHECK(_read_integer_extension(tag, oid, itr, end, 2, &value64));

    *value = (uint16_t)value64;
    result = OE_OK;

done:
    return result;
}

/**
 * Read an enumeration extension.
 */
static oe_result_t _read_enumeration_extension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint8_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t data_length = 0;

    OE_CHECK(_read_extension(
        itr, end, oid, SGX_ENUMERATION_TAG, &data, &data_length));

    if (data_length != 1)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    OE_TRACE_INFO("%s = %d\n", tag, *value);

    *value = *data;
    result = OE_OK;
done:
    return result;
}

/**
 * Read a boolean extension.
 */
static oe_result_t _read_boolean_extension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    bool* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t data_length = 0;
    OE_UNUSED(tag);

    OE_CHECK(
        _read_extension(itr, end, oid, SGX_BOOLEAN_TAG, &data, &data_length));

    if (data_length != 1)
        OE_RAISE(OE_FAILURE);

    *value = *data;
    result = OE_OK;
done:
    return result;
}

/**
 * Get the root SGX extension. The root extension contains a sequence
 * of sgx extension objects.
 */
static oe_result_t _get_sgx_extension(
    oe_cert_t* cert,
    uint8_t* data,
    size_t* data_size)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    size_t size = *data_size;
    OE_CHECK(oe_cert_find_extension(cert, SGX_EXTENSION_OID_STR, data, &size));

    result = OE_OK;
done:
    *data_size = size;
    return result;
}

oe_result_t ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* buffer,
    size_t* buffer_size,
    ParsedExtensionInfo* parsed_info)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* itr = NULL;
    uint8_t* end = NULL;
    size_t data_length = 0;
    uint8_t* tcb_itr = NULL;
    size_t tcb_length = 0;
    uint8_t* tcb_end = NULL;
    uint8_t* config_itr = NULL;
    size_t config_length = 0;
    uint8_t* config_end = NULL;

    if (cert == NULL || buffer == NULL || buffer_size == NULL ||
        parsed_info == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_sgx_extension(cert, buffer, buffer_size));

    itr = buffer;
    end = itr + *buffer_size;
    if (end <= itr)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    // All the extensions are housed within a top-level sequence.
    if (*itr++ != SGX_SEQUENCE_TAG)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    // Assert that the sequence end lines up with length.
    OE_CHECK(_read_asn1_length(&itr, end, &data_length));
    if (itr + data_length != end)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    // Read first extension.
    OE_CHECK(_read_octet_extension(
        "ppid",
        PPID_OID,
        &itr,
        end,
        parsed_info->ppid,
        sizeof(parsed_info->ppid)));

    // Read TCB extension and nested component extensions.
    OE_CHECK(_read_extension(
        &itr, end, TCB_OID, SGX_SEQUENCE_TAG, &tcb_itr, &tcb_length));
    tcb_end = tcb_itr + tcb_length;

    for (uint32_t i = 0; i < OE_COUNTOF(_tcb_comp_svn_oids); ++i)
    {
        OE_CHECK(_read_integer_extension_as_uint8(
            "tcb-comp-svn",
            _tcb_comp_svn_oids[i],
            &tcb_itr,
            tcb_end,
            &parsed_info->comp_svn[i]));
    }

    OE_CHECK(_read_integer_extension_as_uint16(
        "pce-svn", TCB_PCESVN_OID, &tcb_itr, tcb_end, &parsed_info->pce_svn));

    OE_CHECK(_read_octet_extension(
        "tcb-cpu-svn",
        TCB_CPUSVN_OID,
        &tcb_itr,
        tcb_end,
        parsed_info->cpu_svn,
        sizeof(parsed_info->cpu_svn)));

    // Assert that all bytes of tcb extension have been read.
    if (tcb_itr != tcb_end)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    // Read other first level extensions.
    OE_CHECK(_read_octet_extension(
        "PCEID",
        PCEID_OID,
        &itr,
        end,
        parsed_info->pce_id,
        sizeof(parsed_info->pce_id)));

    OE_CHECK(_read_octet_extension(
        "FMSPC",
        FMSPC_OID,
        &itr,
        end,
        parsed_info->fmspc,
        sizeof(parsed_info->fmspc)));

    OE_CHECK(_read_enumeration_extension(
        "sgx-type", SGX_TYPE_OID, &itr, end, &parsed_info->sgx_type));

    if (parsed_info->sgx_type >= 2)
        OE_RAISE(OE_FAILURE);

    if (itr != end)
    {
        // There are two possible optional extensions. The second one have
        // another three sub-extensions nested in it. They are expected to be
        // in increasing order of OIDs. Their values are ignored.
        OE_CHECK(_read_octet_extension(
            "opt_platform_instance_id",
            OPT_PLATFORM_INSTANCE_ID_OID,
            &itr,
            end,
            parsed_info->opt_platform_instance_id,
            sizeof(parsed_info->opt_platform_instance_id)));

        // Read configuration extension and nested component extensions.
        OE_CHECK(_read_extension(
            &itr,
            end,
            OPT_CONFIGURATION_OID,
            SGX_SEQUENCE_TAG,
            &config_itr,
            &config_length));
        config_end = config_itr + config_length;

        _read_boolean_extension(
            "opt-dynamic-platform",
            OPT_DYNAMIC_PLATFORM_OID,
            &config_itr,
            config_end,
            &parsed_info->opt_dynamic_platform);

        _read_boolean_extension(
            "opt-cached-keys",
            OPT_CACHED_KEYS_OID,
            &config_itr,
            config_end,
            &parsed_info->opt_cached_keys);

        _read_boolean_extension(
            "opt_smt_enabled",
            OPT_SMT_ENABLED_OID,
            &config_itr,
            config_end,
            &parsed_info->opt_smt_enabled);

        // Assert that all bytes of configuration extension have been read.
        if (config_itr != config_end)
            OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

        // Assert that the optional extensions have been read.
        if (itr != end)
            OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);
    }

    result = OE_OK;
done:
    return result;
}
