// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "tcbinfo.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "common.h"

#ifdef OE_USE_LIBSGX

// Public key of Intel's root certificate.
static const char* _trusted_root_key_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\n"
    "SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n"
    "-----END PUBLIC KEY-----\n";

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
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* p = *itr;
    if (p < end && *p == ch)
    {
        *itr = _skip_ws(++p, end);
        result = OE_OK;
    }
    return result;
}

// Read an integer literal in current position.
// Only the necessary subset of json numbers are supported.
// Integers must be a sequence of digits.
// Negative and floating point json numbers are not supported.
// Value must fit within an uint64_t.
static oe_result_t _read_integer(
    const uint8_t** itr,
    const uint8_t* end,
    uint64_t* value)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* p = *itr;
    *value = 0;

    if (p < end && _is_digit(*p))
    {
        *value = (uint64_t)(*p - '0');
        ++p;
        while (p < end && _is_digit(*p))
        {
            // Detect overflows.
            if (*value >= OE_UINT64_MAX / 10)
                OE_RAISE(OE_JSON_INFO_PARSE_ERROR);

            *value = *value * 10 + (uint64_t)(*p - '0');
            ++p;
        }

        *itr = _skip_ws(p, end);
        result = OE_OK;
    }
done:
    return result;
}

// Read a string literal in current position.
// Only the necessary subset of json strings are supported.
// JSON escape sequences are not supported.
static oe_result_t _read_string(
    const uint8_t** itr,
    const uint8_t* end,
    const uint8_t** str,
    size_t* length)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* p = *itr;
    *length = 0;

    p = _skip_ws(p, end);
    if (p < end && *p == '"')
    {
        *str = ++p;
        while (p < end && *p != '"')
        {
            if (*p == '\\')
                OE_RAISE(OE_JSON_INFO_PARSE_ERROR);

            ++p;
        }

        if (p < end && *p == '"')
        {
            *length = (size_t)(p - *str);
            *itr = _skip_ws(++p, end);
            result = OE_OK;
        }
    }
done:
    return result;
}

static uint32_t _hex_to_dec(uint8_t hex)
{
    if (hex >= '0' && hex <= '9')
        return (uint32_t)hex - '0';
    if (hex >= 'a' && hex <= 'f')
        return (uint32_t)(hex - 'a') + 10;
    if (hex >= 'A' && hex <= 'F')
        return (uint32_t)(hex - 'A') + 10;
    return 16;
}

// Read a hex string in current position
static oe_result_t _read_hex_string(
    const uint8_t** itr,
    const uint8_t* end,
    uint8_t* bytes,
    size_t length)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* str = NULL;
    size_t str_length = 0;
    uint32_t value = 0;

    OE_CHECK(_read_string(itr, end, &str, &str_length));
    // Each byte takes up two hex digits.
    if (str_length == length * 2)
    {
        for (size_t i = 0; i < length; ++i)
        {
            value =
                (_hex_to_dec(str[i * 2]) << 4) | _hex_to_dec(str[i * 2 + 1]);
            if (value > OE_UCHAR_MAX)
                OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
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
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* name = NULL;
    size_t name_length = 0;
    const uint8_t* tmp_itr = *itr;

    OE_CHECK(_read_string(&tmp_itr, end, &name, &name_length));
    if (name_length == strlen(property_name) &&
        memcmp(property_name, name, name_length) == 0)
    {
        OE_CHECK(_read(':', &tmp_itr, end));
        *itr = tmp_itr;
        result = OE_OK;
    }
done:
    return result;
}

static bool _json_str_equal(
    const uint8_t* str1,
    size_t str1_length,
    const char* str2)
{
    size_t str2_length = strlen(str2);

    // Strings in json stream are not zero terminated.
    // Hence the special comparison function.
    return (str1_length == str2_length) &&
           (memcmp(str1, str2, str2_length) == 0);
}

static oe_result_t _trace_json_string(const uint8_t* str, size_t str_length)
{
    oe_result_t result = OE_OK;
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    char buffer[str_length + 1];
    OE_CHECK(oe_memcpy_s(buffer, sizeof(buffer), str, str_length));
    buffer[str_length] = 0;
    OE_TRACE_INFO("value = %s\n", buffer);

done:
#endif
    return result;
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
static oe_result_t _read_tcb(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_level_t* tcb_level)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
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

        if (value > OE_UCHAR_MAX)
            OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
        tcb_level->sgx_tcb_comp_svn[i] = (uint8_t)value;
    }
    OE_TRACE_INFO("Reading pcesvn\n");
    OE_CHECK(_read_property_name_and_colon("pcesvn", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    OE_TRACE_INFO("value = %lu\n", value);
    OE_CHECK(_read('}', itr, end));

    if (value > OE_USHRT_MAX)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);

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

    // Compare all of the platform's comp svn values with the corresponding
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
static oe_result_t _read_tcb_level(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    oe_tcb_level_t tcb_level = {{0}};
    const uint8_t* status = NULL;
    size_t status_length = 0;

    OE_CHECK(_read('{', itr, end));

    OE_TRACE_INFO("Reading tcb\n");
    OE_CHECK(_read_property_name_and_colon("tcb", itr, end));
    OE_CHECK(_read_tcb(itr, end, &tcb_level));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading status\n");
    OE_CHECK(_read_property_name_and_colon("status", itr, end));
    OE_CHECK(_read_string(itr, end, &status, &status_length));
    OE_CHECK(_trace_json_string(status, status_length));

    OE_CHECK(_read('}', itr, end));

    if (_json_str_equal(status, status_length, "UpToDate"))
        tcb_level.status = OE_TCB_LEVEL_STATUS_UP_TO_DATE;
    else if (_json_str_equal(status, status_length, "OutOfDate"))
        tcb_level.status = OE_TCB_LEVEL_STATUS_OUT_OF_DATE;
    else if (_json_str_equal(status, status_length, "Revoked"))
        tcb_level.status = OE_TCB_LEVEL_STATUS_REVOKED;
    else if (_json_str_equal(status, status_length, "ConfigurationNeeded"))
        tcb_level.status = OE_TCB_LEVEL_STATUS_CONFIGURATION_NEEDED;

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
static oe_result_t _read_tcb_info(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    uint64_t value = 0;
    const uint8_t* date_str = NULL;
    size_t date_size = 0;

    parsed_info->tcb_info_start = *itr;
    OE_CHECK(_read('{', itr, end));

    OE_TRACE_INFO("Reading version\n");
    OE_CHECK(_read_property_name_and_colon("version", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->version = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading issueDate\n");
    OE_CHECK(_read_property_name_and_colon("issueDate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->issue_date) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading nextUpdate\n");
    OE_CHECK(_read_property_name_and_colon("nextUpdate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->next_update) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
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

    // itr is expected to point to the '}' that denotes the end of the tcb
    // object. The signature is generated over the entire object including the
    // '}'.
    parsed_info->tcb_info_size =
        (size_t)(*itr - parsed_info->tcb_info_start + 1);
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
    size_t tcb_info_json_size,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
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
        if (platform_tcb_level->status != OE_TCB_LEVEL_STATUS_UP_TO_DATE)
            OE_RAISE(OE_TCB_LEVEL_INVALID);

        OE_TRACE_INFO("TCB Info json parsing successful.\n");
        result = OE_OK;
    }
done:
    return result;
}

OE_INLINE uint32_t read_uint32(const uint8_t* p)
{
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

OE_INLINE uint64_t read_uint64(const uint8_t* p)
{
    uint64_t temp = 0;
    uint64_t result = 0;
    for (int i = 7; i >= 0; i--)
    {
        temp = p[i];
        result = (result << 8) | temp;
    }
    return result;
}
/**
 * type = qe_identity
 * Schema:
 * {
 *     "version" : integer,
 *    "issueDate" : string,
 *    "nextDate" : string,
 *    "miscselect" : hex string,
 *    "miscselectMask" : hex string,
 *    "attributes" : hex string,
 *    "attributesMask" : hex string,
 *    "mrsigner" : hex string,
 *    "isvprodid" : integer,
 *    "isvsvn" : integer,
 * }
 */
static oe_result_t _read_qe_identity_info(
    const uint8_t** itr,
    const uint8_t* end,
    oe_parsed_qe_identity_info_t* parsed_info)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    uint64_t value = 0;
    const uint8_t* date_str = NULL;
    size_t date_size = 0;
    uint8_t four_bytes_buf[4];
    uint8_t sixteen_bytes_buf[16];

    parsed_info->info_start = *itr;
    OE_CHECK(_read('{', itr, end));

    OE_TRACE_INFO("Reading version\n");
    OE_CHECK(_read_property_name_and_colon("version", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->version = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading issueDate\n");
    OE_CHECK(_read_property_name_and_colon("issueDate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->issue_date) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading nextUpdate\n");
    OE_CHECK(_read_property_name_and_colon("nextUpdate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->next_update) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading miscselect\n");
    OE_CHECK(_read_property_name_and_colon("miscselect", itr, end));
    OE_CHECK(
        _read_hex_string(itr, end, four_bytes_buf, sizeof(four_bytes_buf)));
    parsed_info->miscselect = read_uint32(four_bytes_buf);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading miscselectMask\n");
    OE_CHECK(_read_property_name_and_colon("miscselectMask", itr, end));
    OE_CHECK(
        _read_hex_string(itr, end, four_bytes_buf, sizeof(four_bytes_buf)));
    parsed_info->miscselect_mask = read_uint32(four_bytes_buf);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading attributes.flags\n");
    OE_CHECK(_read_property_name_and_colon("attributes", itr, end));
    OE_CHECK(
        _read_hex_string(
            itr, end, sixteen_bytes_buf, sizeof(sixteen_bytes_buf)));
    parsed_info->attributes.flags = read_uint64(sixteen_bytes_buf);
    parsed_info->attributes.xfrm = read_uint64(sixteen_bytes_buf + 8);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading attributesMask\n");
    OE_CHECK(_read_property_name_and_colon("attributesMask", itr, end));
    OE_CHECK(
        _read_hex_string(
            itr, end, sixteen_bytes_buf, sizeof(sixteen_bytes_buf)));
    parsed_info->attributes_flags_mask = read_uint64(sixteen_bytes_buf);
    parsed_info->attributes_xfrm_mask = read_uint64(sixteen_bytes_buf + 8);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading mrsigner\n");
    OE_CHECK(_read_property_name_and_colon("mrsigner", itr, end));
    OE_CHECK(
        _read_hex_string(
            itr, end, parsed_info->mrsigner, sizeof(parsed_info->mrsigner)));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading isvprodid\n");
    OE_CHECK(_read_property_name_and_colon("isvprodid", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->isvprodid = (uint16_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_INFO("Reading isvsvn\n");
    OE_CHECK(_read_property_name_and_colon("isvsvn", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->isvsvn = (uint16_t)value;

    // itr is expected to point to the '}' that denotes the end of the qe
    // identity object. The signature is generated over the entire object
    // including the '}'.
    parsed_info->info_size = (size_t)(*itr - parsed_info->info_start + 1);
    OE_CHECK(_read('}', itr, end));
    OE_TRACE_INFO("Done with last read\n");
    result = OE_OK;
done:
    OE_TRACE_INFO(
        "Reading _read_qe_identity_info ended with [%s]\n",
        oe_result_str(result));
    return result;
}

/**
 * type = qe_identity_info
 *
 * Schema:
 * {
 *    "qeIdentity" : object of type qe_identity,
 *    "signature" : "hex string"
 * }
 */
oe_result_t oe_parse_qe_identity_info_json(
    const uint8_t* info_json,
    size_t info_json_size,
    oe_parsed_qe_identity_info_t* parsed_info)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;

    const uint8_t* itr = info_json;
    const uint8_t* end = info_json + info_json_size;

    if (info_json == NULL || info_json_size == 0 || parsed_info == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Pointer wrapping.
    if (end <= itr)
        OE_RAISE(OE_INVALID_PARAMETER);

    itr = _skip_ws(itr, end);
    OE_CHECK(_read('{', &itr, end));

    OE_TRACE_INFO("Reading qeIdentity\n");
    OE_CHECK(_read_property_name_and_colon("qeIdentity", &itr, end));
    OE_CHECK(_read_qe_identity_info(&itr, end, parsed_info));
    OE_CHECK(_read(',', &itr, end));

    OE_TRACE_INFO("Reading signature\n");
    OE_CHECK(_read_property_name_and_colon("signature", &itr, end));
    OE_CHECK(
        _read_hex_string(
            &itr, end, parsed_info->signature, sizeof(parsed_info->signature)));
    OE_CHECK(_read('}', &itr, end));
    if (itr == end)
    {
        result = OE_OK;
    }

done:
    OE_TRACE_INFO(
        "oe_parse_qe_identity_info_json ended with [%s]\n",
        oe_result_str(result));
    return result;
}

static oe_result_t _ecdsa_verify(
    oe_ec_public_key_t* publicKey,
    const void* data,
    size_t dataSize,
    sgx_ecdsa256_signature_t* signature)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_t sha256Ctx = {0};
    OE_SHA256 sha256 = {0};
    uint8_t asn1Signature[256];
    size_t asn1SignatureSize = sizeof(asn1Signature);

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

oe_result_t oe_verify_ecdsa256_signature(
    const uint8_t* tcb_info_start,
    size_t tcb_info_size,
    sgx_ecdsa256_signature_t* signature,
    oe_cert_chain_t* tcb_cert_chain)
{
    oe_result_t result = OE_FAILURE;
    oe_cert_t root_cert = {0};
    oe_cert_t leaf_cert = {0};
    oe_ec_public_key_t tcb_root_key = {0};
    oe_ec_public_key_t tcb_signing_key = {0};
    oe_ec_public_key_t trusted_root_key = {0};
    bool root_of_trust_match = false;

    if (tcb_info_start == NULL || tcb_info_size == 0 || signature == NULL ||
        tcb_cert_chain == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_cert_chain_get_root_cert(tcb_cert_chain, &root_cert));
    OE_CHECK(oe_cert_chain_get_leaf_cert(tcb_cert_chain, &leaf_cert));

    OE_CHECK(oe_cert_get_ec_public_key(&root_cert, &tcb_root_key));
    OE_CHECK(oe_cert_get_ec_public_key(&leaf_cert, &tcb_signing_key));

    OE_CHECK(
        _ecdsa_verify(
            &tcb_signing_key, tcb_info_start, tcb_info_size, signature));

    // Ensure that the root certificate matches root of trust.
    OE_CHECK(
        oe_ec_public_key_read_pem(
            &trusted_root_key,
            (const uint8_t*)_trusted_root_key_pem,
            strlen(_trusted_root_key_pem) + 1));

    OE_CHECK(
        oe_ec_public_key_equal(
            &trusted_root_key, &tcb_root_key, &root_of_trust_match));

    if (!root_of_trust_match)
    {
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    OE_TRACE_INFO("tcb info ecdsa attestation succeeded\n");

    result = OE_OK;
done:
    oe_ec_public_key_free(&trusted_root_key);
    oe_ec_public_key_free(&tcb_signing_key);
    oe_ec_public_key_free(&tcb_root_key);

    oe_cert_free(&leaf_cert);
    oe_cert_free(&root_cert);

    return result;
}

#endif
