// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/trace.h>
#include <string.h>
#include "common.h"

#define SGX_EXTENSION_OID_STR "1.2.840.113741.1.13.1"
#define SGX_EXTENSION_OID "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01"

#define PPID_OID SGX_EXTENSION_OID "\x01"

#define TCB_OID SGX_EXTENSION_OID "\x02"

static const char* _TcbCompSvnOids[16] = {
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
#define OPT_DYNAMIC_PLATFORM_OID SGX_EXTENSION_OID "\x06"
#define OPT_CACHED_KEYS_OID SGX_EXTENSION_OID "\x07"

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
    OE_COUNTOF(((ParsedExtensionInfo*)0)->compSvn) ==
    OE_COUNTOF(_TcbCompSvnOids));

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
static oe_result_t _ReadASN1Length(uint8_t** itr, uint8_t* end, size_t* length)
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
            bytes = *p++ - 0x80;
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
static int8_t _OIDEqual(
    uint8_t* oid,
    uint8_t* end,
    size_t oidLength,
    const char* expectedOid)
{
    size_t expectedLength = strlen(expectedOid);
    return (oidLength == expectedLength) && (oid + oidLength < end) &&
           (memcmp(oid, expectedOid, oidLength) == 0);
}

/**
 * Each individual extension is encoded as an ASN1 sequence object
 * that consists of two objects: oid object, data object.
 * extension = (SGX_SEQUENCE_TAG sequenceLength
 *                 (SGX_OBJECT_ID_TAG oidLength oidBytes)
 *                 (dataTag dataLength dataBytes)
 *              )
*/
static oe_result_t _ReadExtension(
    uint8_t** itr,
    uint8_t* end,
    const char* expectedOid,
    uint8_t dataTag,
    uint8_t** data,
    size_t* dataLength)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* p = NULL;
    size_t length = 0;
    size_t oidLength = 0;
    uint8_t* objectEnd = NULL;

    if (itr == NULL || *itr == NULL || end == NULL || expectedOid == NULL ||
        data == NULL || dataLength == NULL)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    p = *itr;
    if (p >= end)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    if (*p++ == SGX_SEQUENCE_TAG && p < end)
    {
        OE_CHECK(_ReadASN1Length(&p, end, &length));
        if (p + length <= end && length > 0)
        {
            // Record the end of current sequence object.
            objectEnd = p + length;
            if (*p++ == SGX_OBJECT_ID_TAG && p < end)
            {
                OE_CHECK(_ReadASN1Length(&p, end, &oidLength));
                if (!_OIDEqual(p, end, oidLength, expectedOid))
                    OE_RAISE(OE_FAILURE);
                p += oidLength;
                if (p < end && *p++ == dataTag)
                {
                    OE_CHECK(_ReadASN1Length(&p, end, dataLength));
                    if (p + *dataLength == objectEnd)
                    {
                        *data = p;
                        *itr = objectEnd;
                        result = OE_OK;
                    }
                }
            }
        }
    }
done:
    return result;
}

static void _TraceHexDump(const char* tag, const uint8_t* data, size_t size)
{
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    OE_TRACE_INFO("%s = ", tag);
    oe_hex_dump(data, size);
#endif
}

/**
 * Read an extension with given oid and data of type octet string.
 */
static oe_result_t _ReadOctetExtension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint8_t* buffer,
    size_t length)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t dataLength = 0;

    OE_CHECK(
        _ReadExtension(
            itr, end, oid, SGX_OCTET_STRING_TAG, &data, &dataLength));
    if (dataLength != length)
        OE_RAISE(OE_FAILURE);

    memcpy(buffer, data, dataLength);
    _TraceHexDump(tag, buffer, dataLength);
    result = OE_OK;
done:
    return result;
}

/**
 * Read an Integer extension with given oid and check that the value fits in
 * the specified number of bytes.
 */
static oe_result_t _ReadIntegerExtension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    size_t numBytes,
    uint64_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t dataLength = 0;

    OE_CHECK(
        _ReadExtension(itr, end, oid, SGX_INTEGER_TAG, &data, &dataLength));

    *value = 0;
    for (size_t i = 0; i < dataLength; ++i)
    {
        *value = (*value << 8) | (data[i]);
    }

    // If the leftmost bit of the integer is 1, then it is prefixed with a zero
    // byte to indicate that it is a positive number, rather than a negative
    // number. Negative numbers in two's complement form have the leftmost bit
    // set. Thus, dataLength can be numBytes + 1, in which case the first byte
    // must be zero.
    if (dataLength == numBytes + 1)
    {
        if (data[0] != 0)
            OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);
    }
    else
    {
        if (dataLength > numBytes)
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
static oe_result_t _ReadIntegerExtensionAsUint8(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint8_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint64_t value64 = 0;

    OE_CHECK(
        _ReadIntegerExtension(tag, oid, itr, end, sizeof(uint8_t), &value64));

    *value = (uint8_t)value64;
    result = OE_OK;

done:
    return result;
}

/**
 * Read an Integer extension with given oid and check that the value fits in a
 * uint16_t.
 */
static oe_result_t _ReadIntegerExtensionAsUint16(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint16_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint64_t value64 = 0;

    OE_CHECK(_ReadIntegerExtension(tag, oid, itr, end, 2, &value64));

    *value = (uint16_t)value64;
    result = OE_OK;

done:
    return result;
}

/**
 * Read an enumeration extension.
 */
static oe_result_t _ReadEnumerationExtension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint8_t* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t dataLength = 0;

    OE_CHECK(
        _ReadExtension(itr, end, oid, SGX_ENUMERATION_TAG, &data, &dataLength));

    if (dataLength != 1)
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
static oe_result_t _ReadBooleanExtension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    bool* value)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* data = NULL;
    size_t dataLength = 0;

    OE_CHECK(
        _ReadExtension(itr, end, oid, SGX_BOOLEAN_TAG, &data, &dataLength));

    if (dataLength != 1)
        OE_RAISE(OE_FAILURE);

    OE_TRACE_INFO("%s = %d\n", tag, *value);

    *value = *data;
    result = OE_OK;
done:
    return result;
}

/**
 * Get the root SGX extension. The root extension contains a sequence
 * of sgx extension objects.
 */
static oe_result_t _GetSGXExtension(
    oe_cert_t* cert,
    uint8_t* data,
    size_t* dataSize)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    size_t size = *dataSize;
    OE_CHECK(oe_cert_find_extension(cert, SGX_EXTENSION_OID_STR, data, &size));

    result = OE_OK;
done:
    *dataSize = size;
    return result;
}

oe_result_t ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* buffer,
    size_t* bufferSize,
    ParsedExtensionInfo* parsedInfo)
{
    oe_result_t result = OE_INVALID_SGX_CERTIFICATE_EXTENSIONS;
    uint8_t* itr = NULL;
    uint8_t* end = NULL;
    size_t dataLength = 0;
    uint8_t* tcbItr = NULL;
    size_t tcbLength = 0;
    uint8_t* tcbEnd = NULL;

    if (cert == NULL || buffer == NULL || bufferSize == NULL ||
        parsedInfo == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_GetSGXExtension(cert, buffer, bufferSize));

    itr = buffer;
    end = itr + *bufferSize;
    if (end <= itr)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    // All the extensions are housed within a top-level sequence.
    if (*itr++ != SGX_SEQUENCE_TAG)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    // Assert that the sequence end lines up with length.
    OE_CHECK(_ReadASN1Length(&itr, end, &dataLength));
    if (itr + dataLength != end)
        OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);

    // Read first extension.
    OE_CHECK(
        _ReadOctetExtension(
            "ppid",
            PPID_OID,
            &itr,
            end,
            parsedInfo->ppid,
            sizeof(parsedInfo->ppid)));

    // Read TCB extension and nested component extensions.
    OE_CHECK(
        _ReadExtension(
            &itr, end, TCB_OID, SGX_SEQUENCE_TAG, &tcbItr, &tcbLength));
    tcbEnd = tcbItr + tcbLength;

    for (uint32_t i = 0; i < OE_COUNTOF(_TcbCompSvnOids); ++i)
    {
        OE_CHECK(
            _ReadIntegerExtensionAsUint8(
                "tcb-comp-svn",
                _TcbCompSvnOids[i],
                &tcbItr,
                tcbEnd,
                &parsedInfo->compSvn[i]));
    }

    OE_CHECK(
        _ReadIntegerExtensionAsUint16(
            "pce-svn", TCB_PCESVN_OID, &tcbItr, tcbEnd, &parsedInfo->pceSvn));

    OE_CHECK(
        _ReadOctetExtension(
            "tcb-cpu-svn",
            TCB_CPUSVN_OID,
            &tcbItr,
            tcbEnd,
            parsedInfo->cpuSvn,
            sizeof(parsedInfo->cpuSvn)));

    // Assert that all bytes of tcb extension have been read.
    if (tcbItr != tcbEnd)
        OE_RAISE(OE_FAILURE);

    // Read other first level extensions.
    OE_CHECK(
        _ReadOctetExtension(
            "PCEID",
            PCEID_OID,
            &itr,
            end,
            parsedInfo->pceId,
            sizeof(parsedInfo->pceId)));

    OE_CHECK(
        _ReadOctetExtension(
            "FMSPC",
            FMSPC_OID,
            &itr,
            end,
            parsedInfo->fmspc,
            sizeof(parsedInfo->fmspc)));

    OE_CHECK(
        _ReadEnumerationExtension(
            "sgx-type", SGX_TYPE_OID, &itr, end, &parsedInfo->sgxType));

    if (parsedInfo->sgxType >= 2)
        OE_RAISE(OE_FAILURE);

    if (itr != end)
    {
        // There are two possible optional extensions. They are expected to be
        // in increasing order of OIDs. Their values are ignored.
        _ReadBooleanExtension(
            "opt-dynamic-platform",
            OPT_DYNAMIC_PLATFORM_OID,
            &itr,
            end,
            &parsedInfo->optDynamicPlatform);

        _ReadBooleanExtension(
            "opt-cached-keys",
            OPT_CACHED_KEYS_OID,
            &itr,
            end,
            &parsedInfo->optCachedKeys);

        // Assert that the optional extensions have been read.
        if (itr != end)
            OE_RAISE(OE_INVALID_SGX_CERTIFICATE_EXTENSIONS);
    }

    result = OE_OK;
done:
    return result;
}
