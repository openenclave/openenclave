// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//#define OE_TRACE_LEVEL 2
#include <openenclave/enclave.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/trace.h>
#include <string.h>

#define SGX_EXTENSION_OID_STR "1.2.840.113741.1.13.1"
#define SGX_EXTENSION_OID "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01"
#define PPID_OID SGX_EXTENSION_OID "\x01"
#define TCB_OID SGX_EXTENSION_OID "\x02"
#define TCB_COMP_SVN01_OID TCB_OID "\x01"
#define TCB_COMP_SVN02_OID TCB_OID "\x02"
#define TCB_COMP_SVN03_OID TCB_OID "\x03"
#define TCB_COMP_SVN04_OID TCB_OID "\x04"
#define TCB_COMP_SVN05_OID TCB_OID "\x05"
#define TCB_COMP_SVN06_OID TCB_OID "\x06"
#define TCB_COMP_SVN07_OID TCB_OID "\x07"
#define TCB_COMP_SVN08_OID TCB_OID "\x08"
#define TCB_COMP_SVN09_OID TCB_OID "\x09"
#define TCB_COMP_SVN10_OID TCB_OID "\x0a"
#define TCB_COMP_SVN11_OID TCB_OID "\x0b"
#define TCB_COMP_SVN12_OID TCB_OID "\x0c"
#define TCB_COMP_SVN13_OID TCB_OID "\x0d"
#define TCB_COMP_SVN14_OID TCB_OID "\x0e"
#define TCB_COMP_SVN15_OID TCB_OID "\x0f"
#define TCB_COMP_SVN16_OID TCB_OID "\x10"
#define TCB_PCESVN_OID TCB_OID "\x11"
#define TCB_CPUSVN_OID TCB_OID "\x12"
#define PCEID_OID SGX_EXTENSION_OID "\x03"
#define FMSPC_OID SGX_EXTENSION_OID "\x04"
#define SGX_TYPE_OID SGX_EXTENSION_OID "\x05"
#define OPT_DYNAMIC_PLATFORM_OID SGX_EXTENSION_OID "\x06"
#define OPT_CACHED_KEYS_OID SGX_EXTENSION_OID "\x07"

#define ASN1_BOOLEAN_TAG (0x01)
#define ASN1_INTEGER_TAG (0x02)
#define ASN1_SEQUENCE_TAG (0x30)
#define ASN1_OCTET_STRING_TAG (0x04)
#define ASN1_OBJECT_ID_TAG (0x06)
#define ASN1_ENUMERATION_TAG (0x0a)

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
static oe_result_t _ReadASN1Length(
    uint8_t** itr,
    uint8_t* end,
    uint64_t* length)
{
    oe_result_t result = OE_FAILURE;
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
            result = OE_OK;
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
                result = OE_OK;
            }
        }
    }
done:

    return result;
}

/**
 * Check whether an oid is equal to the given byte value string.
 */
static int8_t _OIDEqual(
    uint8_t* oid,
    uint8_t* end,
    uint32_t oidLength,
    const char* expectedOid)
{
    uint32_t expectedLength = strlen(expectedOid);
    return (oidLength == expectedLength) && (oid + oidLength < end) &&
           (memcmp(oid, expectedOid, oidLength) == 0);
}

/**
 * Each individual extension is encoded as an ASN1 sequence object
 * that consists of two objects: oid object, data object.
 * extension = (ASN1_SEQUENCE_TAG sequenceLength
 *                 (ASN1_OBJECT_ID_TAG oidLength oidBytes)
 *                 (dataTag dataLength dataBytes)*
 *              )
*/
static oe_result_t _ReadExtension(
    uint8_t** itr,
    uint8_t* end,
    const char* expectedOid,
    uint8_t dataTag,
    uint8_t** data,
    uint64_t* dataLength)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* p = NULL;
    uint64_t length = 0;
    uint64_t oidLength = 0;
    uint8_t* objectEnd = NULL;

    if (itr == NULL || *itr == NULL || end == NULL || expectedOid == NULL ||
        data == NULL || dataLength == NULL)
        return false;

    p = *itr;
    if (p >= end)
        OE_RAISE(OE_FAILURE);

    if (*p++ == ASN1_SEQUENCE_TAG && p < end)
    {
        OE_CHECK(_ReadASN1Length(&p, end, &length));
        if (p + length <= end && length > 0)
        {
            // Record the end of current sequence object.
            objectEnd = p + length;
            if (*p++ == ASN1_OBJECT_ID_TAG && p < end)
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

static void _TraceHexDump(const char* tag, const uint8_t* data, uint32_t size)
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
    uint32_t length)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* data = NULL;
    uint64_t dataLength = 0;

    OE_CHECK(
        _ReadExtension(
            itr, end, oid, ASN1_OCTET_STRING_TAG, &data, &dataLength));
    if (dataLength != length)
        OE_RAISE(OE_FAILURE);

    oe_memcpy(buffer, data, dataLength);
    _TraceHexDump(tag, buffer, dataLength);
    result = OE_OK;
done:
    return result;
}

/**
 * Read an extension with given oid and data of type integer.
 */
static oe_result_t _ReadIntegerExtension(
    const char* tag,
    const char* oid,
    uint8_t** itr,
    uint8_t* end,
    uint64_t* value)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* data = NULL;
    uint64_t dataLength = 0;

    OE_CHECK(
        _ReadExtension(itr, end, oid, ASN1_INTEGER_TAG, &data, &dataLength));
    *value = 0;
    for (uint32_t i = 0; i < dataLength; ++i)
    {
        *value = (*value << 8) | data[i];
    }

    OE_TRACE_INFO("%s = %lu\n", tag, *value);

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
    uint32_t* dataSize)
{
    oe_result_t result = OE_FAILURE;
    uint64_t size = *dataSize;
    OE_CHECK(oe_cert_find_extension(cert, SGX_EXTENSION_OID_STR, data, &size));
    result = OE_OK;
done:
    *dataSize = size;
    return result;
}

oe_result_t ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* buffer,
    uint32_t* bufferSize,
    ParsedExtensionInfo* parsedInfo)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* itr = NULL;
    uint8_t* end = NULL;
    uint8_t* data = NULL;
    uint64_t dataLength = 0;
    uint8_t* tcbItr = NULL;
    uint64_t tcbLength = 0;
    uint8_t* tcbEnd = NULL;
    uint8_t readDynamicPlatform = 0;
    uint8_t readCachedKeys = 0;

    if (cert == NULL || buffer == NULL || bufferSize == NULL ||
        parsedInfo == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_GetSGXExtension(cert, buffer, bufferSize));

    itr = buffer;
    end = itr + *bufferSize;

    // All the extensions are housed within a top-level sequence.
    if (*itr++ != ASN1_SEQUENCE_TAG)
        OE_RAISE(OE_FAILURE);

    // Assert that the sequence end lines up with length.
    OE_CHECK(_ReadASN1Length(&itr, end, &dataLength));
    if (itr + dataLength != end)
        OE_RAISE(OE_FAILURE);

    // Read first extension.
    OE_CHECK(
        _ReadOctetExtension(
            "ppid",
            PPID_OID,
            &itr,
            end,
            parsedInfo->ppid,
            sizeof(parsedInfo->ppid)));

    // Read TCB Extenstion and nested component extensions.
    OE_CHECK(
        _ReadExtension(
            &itr, end, TCB_OID, ASN1_SEQUENCE_TAG, &tcbItr, &tcbLength));
    tcbEnd = tcbItr + tcbLength;

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn01",
            TCB_COMP_SVN01_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[0]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn02",
            TCB_COMP_SVN02_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[1]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn03",
            TCB_COMP_SVN03_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[2]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn04",
            TCB_COMP_SVN04_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[3]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn05",
            TCB_COMP_SVN05_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[4]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn06",
            TCB_COMP_SVN06_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[5]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn07",
            TCB_COMP_SVN07_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[6]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn08",
            TCB_COMP_SVN08_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[7]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn09",
            TCB_COMP_SVN09_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[8]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn10",
            TCB_COMP_SVN10_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[9]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn11",
            TCB_COMP_SVN11_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[10]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn12",
            TCB_COMP_SVN12_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[11]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn13",
            TCB_COMP_SVN13_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[12]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn14",
            TCB_COMP_SVN14_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[13]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn15",
            TCB_COMP_SVN15_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[14]));

    OE_CHECK(
        _ReadIntegerExtension(
            "tcb-comp-svn16",
            TCB_COMP_SVN16_OID,
            &tcbItr,
            tcbEnd,
            &parsedInfo->compSvn[15]));

    OE_CHECK(
        _ReadExtension(
            &tcbItr,
            tcbEnd,
            TCB_PCESVN_OID,
            ASN1_INTEGER_TAG,
            &data,
            &dataLength));
    if (dataLength != 1)
        OE_RAISE(OE_FAILURE);
    parsedInfo->pceSvn = *data;
    OE_TRACE_INFO("tcb-pce-svn = %d\n", parsedInfo->pceSvn);

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
        _ReadExtension(
            &itr, end, SGX_TYPE_OID, ASN1_ENUMERATION_TAG, &data, &dataLength));
    if (dataLength != 1)
        OE_RAISE(OE_FAILURE);
    parsedInfo->sgxType = *data;
    OE_TRACE_INFO("sgx-type = %d\n", parsedInfo->sgxType);

    // Read the two optional extensions. They can be in any order.
    // Therefore iterate twice. Make sure that there are no duplicates.
    for (uint32_t i = 0; i < 2; ++i)
    {
        if (_ReadExtension(
                &itr,
                end,
                OPT_DYNAMIC_PLATFORM_OID,
                ASN1_BOOLEAN_TAG,
                &data,
                &dataLength) == OE_OK)
        {
            if (readDynamicPlatform || dataLength != 1)
                OE_RAISE(OE_FAILURE);
            parsedInfo->optDynamicPlatform = *data ? 1 : 0;
            OE_TRACE_INFO(
                "opt-dynamic-platform = %d\n", parsedInfo->optDynamicPlatform);
            readDynamicPlatform = 1;
        }
        if (_ReadExtension(
                &itr,
                end,
                OPT_CACHED_KEYS_OID,
                ASN1_BOOLEAN_TAG,
                &data,
                &dataLength) == OE_OK)
        {
            if (readCachedKeys || dataLength != 1)
                OE_RAISE(OE_FAILURE);
            parsedInfo->optCachedKeys = *data ? 1 : 0;
            OE_TRACE_INFO(
                "opt-cached-keys = %d\n", parsedInfo->optDynamicPlatform);
            readCachedKeys = 1;
        }
    }

    // Assert that all content has been read.
    if (itr != end)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;
done:
    return result;
}
