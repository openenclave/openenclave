// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "tcbinfo.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>

#ifdef OE_USE_LIBSGX

OE_INLINE uint8_t _is_space(uint8_t c)
{
    return (
        c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' ||
        c == '\r' || c == '\0');
}

// Skip white space.
static const uint8_t* _skip_ws(const uint8_t* itr, const uint8_t* end)
{
    while (itr < end && _is_space(*itr))
        ++itr;
    return itr;
}

OE_INLINE uint8_t _is_digit(uint8_t c)
{
    return (c >= '0' && c <= '9');
}

// Read a specific character at current position.
// Consume and skip trailing whitespace.
static oe_result_t _read(char ch, const uint8_t** itr, const uint8_t* end)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* p = *itr;
    if (p < end && *p == ch)
    {
        *itr = _skip_ws(++p, end);
        result = OE_OK;
    }
    return result;
}

// Read an integer literal in current position.
static oe_result_t _read_integer(
    const uint8_t** itr,
    const uint8_t* end,
    uint64_t* value)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* p = *itr;
    *value = 0;

    if (p < end && _is_digit(*p))
    {
        *value = *p - '0';
        ++p;
        while (p < end && _is_digit(*p))
        {
            *value = *value * 10 + (*p - '0');
            ++p;
        }

        *itr = _skip_ws(p, end);
        result = OE_OK;
    }

    return result;
}

// Read a string literal in current position
static oe_result_t _read_string(
    const uint8_t** itr,
    const uint8_t* end,
    const uint8_t** str,
    uint32_t* length)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* p = *itr;

    p = _skip_ws(p, end);
    if (p < end && *p == '"')
    {
        *str = ++p;
        while (p < end && *p != '"')
            ++p;

        if (p < end && *p == '"')
        {
            *length = p - *str;
            *itr = _skip_ws(++p, end);
            result = OE_OK;
        }
    }

    return result;
}

static uint32_t _hex_to_dec(uint8_t hex)
{
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    if (hex >= 'a' && hex <= 'f')
        return (hex - 'a') + 10;
    if (hex >= 'A' && hex <= 'F')
        return (hex - 'A') + 10;
    return 16;
}

// Read a hex string in current position
static oe_result_t _read_hex_string(
    const uint8_t** itr,
    const uint8_t* end,
    uint8_t* bytes,
    uint32_t length)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* str = NULL;
    uint32_t str_length = 0;
    uint16_t value = 0;

    OE_CHECK(_read_string(itr, end, &str, &str_length));
    // Each byte takes up two hex digits.
    if (str_length == length * 2)
    {
        for (uint32_t i = 0; i < length; ++i)
        {
            value =
                (_hex_to_dec(str[i * 2]) << 4) | _hex_to_dec(str[i * 2 + 1]);
            if (value > OE_MAX_UCHAR)
                OE_RAISE(OE_FAILURE);
            bytes[i] = (uint8_t)value;
        }

        result = OE_OK;
    }
done:
    return result;
}

static oe_result_t _read_property_name_and_colon(
    const char* property_name,
    const uint8_t** itr,
    const uint8_t* end)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* name = NULL;
    uint32_t name_length = 0;

    OE_CHECK(_read_string(itr, end, &name, &name_length));
    if (name_length == oe_strlen(property_name) &&
        oe_memcmp(property_name, name, name_length) == 0)
    {
        OE_CHECK(_read(':', itr, end));
        result = OE_OK;
    }
done:
    return result;
}

static bool _json_str_equal(
    const uint8_t* str1,
    uint32_t str1_length,
    const char* str2)
{
    uint32_t str2_length = (uint32_t)oe_strlen(str2);

    // Strings in json stream are not zero terminated.
    // Hence the special comparison function.
    return (str1_length == str2_length) &&
           (oe_memcmp(str1, str2, str2_length) == 0);
}

static void _trace_json_string(const uint8_t* str, uint32_t str_length)
{
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    char buffer[str_length + 1];
    oe_memcpy(buffer, str, str_length);
    buffer[str_length] = 0;
    OE_TRACE_INFO("value = %s\n", buffer);
#endif
}

/**
 * Type: tcb
 * Schema:
 * {
 *    "sgxtcbcomp01svn": uint8_t,
 *    "sgxtcbcomp02svn": uint8_t,
 *    ...
 *    "sgxtcbcomp16svn": uint8_t,
 *    "pcesvn": uint16_t
 * }
 */
oe_result_t _read_tcb(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_level_t* tcb_level)
{
    oe_result_t result = OE_FAILURE;
    uint64_t value = 0;

    static const char* _comp_names[] = {"sgxtcbcomp01svn",
                                        "sgxtcbcomp02svn",
                                        "sgxtcbcomp03svn",
                                        "sgxtcbcomp04svn",
                                        "sgxtcbcomp05svn",
                                        "sgxtcbcomp06svn",
                                        "sgxtcbcomp07svn",
                                        "sgxtcbcomp08svn",
                                        "sgxtcbcomp09svn",
                                        "sgxtcbcomp10svn",
                                        "sgxtcbcomp11svn",
                                        "sgxtcbcomp12svn",
                                        "sgxtcbcomp13svn",
                                        "sgxtcbcomp14svn",
                                        "sgxtcbcomp15svn",
                                        "sgxtcbcomp16svn"};
    OE_STATIC_ASSERT(
        OE_COUNTOF(_comp_names) == OE_COUNTOF(tcb_level->sgx_tcb_comp_svn));

    OE_CHECK(_read('{', itr, end));

    for (uint32_t i = 0; i < OE_COUNTOF(_comp_names); ++i)
    {
        OE_TRACE_INFO("Reading %s\n", _comp_names[i]);
        OE_CHECK(_read_property_name_and_colon(_comp_names[i], itr, end));
        OE_CHECK(_read_integer(itr, end, &value));
        OE_TRACE_INFO("value = %lu\n", value);
        OE_CHECK(_read(',', itr, end));

        if (value > OE_MAX_UCHAR)
            OE_RAISE(OE_FAILURE);
        tcb_level->sgx_tcb_comp_svn[i] = (uint8_t)value;
    }
    OE_TRACE_INFO("Reading pcesvn\n");
    OE_CHECK(_read_property_name_and_colon("pcesvn", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    OE_TRACE_INFO("value = %lu\n", value);
    OE_CHECK(_read('}', itr, end));

    if (value > OE_MAX_USHORT)
        OE_RAISE(OE_FAILURE);

    tcb_level->pce_svn = (uint16_t)value;
    result = OE_OK;
done:
    return result;
}

// Algorithm specified by Intel, reworded:
// 1. Go over the sorted collection of TCB levels in the JSON.
// 2. Choose the first tcb level for which  all of the platform's comp svn
// values and pcesvn values are greater than or equal to corresponding values of
// the tcb level.
// 3. The status of the platform's tcb level is the status of the chosen tcb
// level.
// 4. If no tcb level was chosen, then the status of the platform is unknown.
static void _determine_platform_tcb_level(
    oe_tcb_level_t* platform_tcb_level,
    oe_tcb_level_t* tcb_level)
{
    // If the platform's status has already been determined, return.
    if (platform_tcb_level->status != OE_TCB_LEVEL_STATUS_UNKNOWN)
        return;

    // Compare all  of the platform's comp svn values with the corresponding
    // values in the current tcb level.
    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level->sgx_tcb_comp_svn);
         ++i)
    {
        if (platform_tcb_level->sgx_tcb_comp_svn[i] <
            tcb_level->sgx_tcb_comp_svn[i])
            return;
    }
    if (platform_tcb_level->pce_svn < tcb_level->pce_svn)
        return;

    // If all the values of the tcb level are less than corresponding values of
    // the platform, then the platform's status is the status of the current tcb
    // level.
    platform_tcb_level->status = tcb_level->status;
}

/**
 * Type: tcbLevel
 * Schema:
 * {
 *    "tcb" : object of type tcb
 *    "status": one of "UpToDate" or "OutOfDate" or "Revoked"
 * }
 */
oe_result_t _read_tcb_level(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_FAILURE;
    oe_tcb_level_t tcb_level = {0};
    const uint8_t* status = NULL;
    uint32_t status_length = 0;

    OE_CHECK(_read('{', itr, end));

    OE_TRACE_INFO("Reading tcb\n");
    OE_CHECK(_read_property_name_and_colon("tcb", itr, end));
    OE_CHECK(_read_tcb(itr, end, &tcb_level));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading status\n");
    OE_CHECK(_read_property_name_and_colon("status", itr, end));
    OE_CHECK(_read_string(itr, end, &status, &status_length));
    _trace_json_string(status, status_length);

    OE_CHECK(_read('}', itr, end));

    if (_json_str_equal(status, status_length, "UpToDate"))
        tcb_level.status = OE_TCB_LEVEL_STATUS_UP_TO_DATE;
    else if (_json_str_equal(status, status_length, "OutOfDate"))
        tcb_level.status = OE_TCB_LEVEL_STATUS_OUT_OF_DATE;
    else if (_json_str_equal(status, status_length, "Revoked"))
        tcb_level.status = OE_TCB_LEVEL_STATUS_REVOKED;

    if (tcb_level.status != OE_TCB_LEVEL_STATUS_UNKNOWN)
    {
        _determine_platform_tcb_level(platform_tcb_level, &tcb_level);
        result = OE_OK;
    }

done:
    return result;
}

/**
 * type = tcbInfo
 * Schema:
 * {
 *    "version" : integer,
 *    "issueDate" : string,
 *    "fmspc" : "hex string"
 *    "tcbLevels" : [ objects of type tcbLevel ]
 * }
 */
oe_result_t _read_tcb_info(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_FAILURE;
    uint64_t value = 0;

    parsed_info->tcb_info_start = *itr;
    OE_CHECK(_read('{', itr, end));

    OE_TRACE_INFO("Reading version\n");
    OE_CHECK(_read_property_name_and_colon("version", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->version = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading issueDate\n");
    OE_CHECK(_read_property_name_and_colon("issueDate", itr, end));
    OE_CHECK(
        _read_string(
            itr, end, &parsed_info->issue_date, &parsed_info->issue_date_size));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading fmspc\n");
    OE_CHECK(_read_property_name_and_colon("fmspc", itr, end));
    OE_CHECK(
        _read_hex_string(
            itr, end, parsed_info->fmspc, sizeof(parsed_info->fmspc)));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading tcbLevels\n");
    OE_CHECK(_read_property_name_and_colon("tcbLevels", itr, end));
    OE_CHECK(_read('[', itr, end));
    while (*itr < end)
    {
        OE_CHECK(_read_tcb_level(itr, end, platform_tcb_level, parsed_info));
        // Read end of array or comma separator.
        if (*itr < end && **itr == ']')
            break;

        OE_CHECK(_read(',', itr, end));
    }
    OE_CHECK(_read(']', itr, end));

    parsed_info->tcb_info_end = *itr;
    OE_CHECK(_read('}', itr, end));

    result = OE_OK;
done:
    return result;
}

/**
 * Schema:
 * {
 *    "tcbInfo" : object of type tcbInfo,
 *    "signature" : "hex string"
 * }
 */
oe_result_t oe_parse_tcb_info_json(
    const uint8_t* tcb_info_json,
    uint32_t tcb_info_json_size,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* itr = tcb_info_json;
    const uint8_t* end = tcb_info_json + tcb_info_json_size;

    if (tcb_info_json == NULL || tcb_info_json_size == 0 ||
        platform_tcb_level == NULL || parsed_info == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Pointer wrapping.
    if (end <= itr)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (platform_tcb_level->status != OE_TCB_LEVEL_STATUS_UNKNOWN)
        OE_RAISE(OE_INVALID_PARAMETER);

    itr = _skip_ws(itr, end);
    OE_CHECK(_read('{', &itr, end));

    OE_TRACE_INFO("Reading tcbInfo\n");
    OE_CHECK(_read_property_name_and_colon("tcbInfo", &itr, end));
    OE_CHECK(_read_tcb_info(&itr, end, platform_tcb_level, parsed_info));
    OE_CHECK(_read(',', &itr, end));

    OE_TRACE_INFO("Reading signature\n");
    OE_CHECK(_read_property_name_and_colon("signature", &itr, end));
    OE_CHECK(
        _read_hex_string(
            &itr, end, parsed_info->signature, sizeof(parsed_info->signature)));

    OE_CHECK(_read('}', &itr, end));

    if (itr == end)
    {
        OE_TRACE_INFO("TCB Info json parsing successful.\n");
        result = OE_OK;
    }
done:
    return result;
}

static oe_result_t _ECDSAVerify(
    oe_ec_public_key_t* publicKey,
    const void* data,
    uint32_t dataSize,
    sgx_ecdsa256_signature_t* signature)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_t sha256Ctx = {0};
    OE_SHA256 sha256 = {0};
    uint8_t asn1Signature[256];
    uint64_t asn1SignatureSize = sizeof(asn1Signature);

    OE_CHECK(oe_sha256_init(&sha256Ctx));
    OE_CHECK(oe_sha256_update(&sha256Ctx, data, dataSize));
    OE_CHECK(oe_sha256_final(&sha256Ctx, &sha256));

    OE_CHECK(
        oe_ecdsa_signature_write_der(
            asn1Signature,
            &asn1SignatureSize,
            signature->r,
            sizeof(signature->r),
            signature->s,
            sizeof(signature->s)));

    OE_CHECK(
        oe_ec_public_key_verify(
            publicKey,
            OE_HASH_TYPE_SHA256,
            (uint8_t*)&sha256,
            sizeof(sha256),
            asn1Signature,
            asn1SignatureSize));

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_verify_tcb_signature(
    const uint8_t* tcb_info_json,
    uint32_t tcb_info_json_size,
    oe_parsed_tcb_info_t* parsed_tcb_info,
    uint8_t* buffer,
    uint32_t bufferSize,
    oe_cert_chain_t* tcb_cert_chain)
{
    oe_result_t result = OE_FAILURE;
    const uint8_t* tcb_info_json_end = tcb_info_json + tcb_info_json_size;
    oe_cert_t leaf_cert = {0};
    oe_ec_public_key_t tcb_signing_key = {0};

    if (tcb_info_json == NULL || tcb_info_json_size == 0 ||
        parsed_tcb_info == NULL || buffer == NULL ||
        bufferSize < tcb_info_json_size || tcb_cert_chain == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (parsed_tcb_info->tcb_info_start < tcb_info_json ||
        parsed_tcb_info->tcb_info_start >= tcb_info_json_end)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (parsed_tcb_info->tcb_info_end < tcb_info_json ||
        parsed_tcb_info->tcb_info_end >= tcb_info_json_end)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (parsed_tcb_info->tcb_info_start >= parsed_tcb_info->tcb_info_end)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (*parsed_tcb_info->tcb_info_start != '{' ||
        *parsed_tcb_info->tcb_info_end != '}')
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_cert_chain_get_leaf_cert(tcb_cert_chain, &leaf_cert));
    OE_CHECK(oe_cert_get_ec_public_key(&leaf_cert, &tcb_signing_key));

    OE_CHECK(
        _ECDSAVerify(
            &tcb_signing_key,
            parsed_tcb_info->tcb_info_start,
            1 + parsed_tcb_info->tcb_info_end - parsed_tcb_info->tcb_info_start,
            (sgx_ecdsa256_signature_t*)parsed_tcb_info->signature));
    OE_TRACE_INFO("tcb info ecdsa attestation succeeded\n");

    result = OE_OK;
done:
    oe_ec_public_key_free(&tcb_signing_key);

    return result;
}

#endif
