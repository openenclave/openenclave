// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "tcbinfo.h"
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common.h"

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
    if (name_length == oe_strlen(property_name) &&
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
    size_t str2_length = oe_strlen(str2);

    // Strings in json stream are not zero terminated.
    // Hence the special comparison function.
    return (str1_length == str2_length) &&
           (memcmp(str1, str2, str2_length) == 0);
}

static oe_result_t _trace_json_string(const uint8_t* str, size_t str_length)
{
    oe_result_t result = OE_OK;

    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_VERBOSE)
    {
        char* buffer = (char*)oe_malloc(str_length + 1);
        if (buffer)
        {
            OE_CHECK(oe_memcpy_s(buffer, str_length + 1, str, str_length));
            buffer[str_length] = 0;
            OE_TRACE_VERBOSE("value = %s\n", buffer);
            oe_free(buffer);
        }
        else
        {
            OE_RAISE(OE_OUT_OF_MEMORY);
        }
    }
done:
    return result;
}

static oe_tcb_level_status_t _parse_tcb_status(
    const uint8_t* str,
    size_t length)
{
    oe_tcb_level_status_t status;
    status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;

    if (_json_str_equal(str, length, "UpToDate"))
        status.fields.up_to_date = 1;
    else if (_json_str_equal(str, length, "OutOfDate"))
        status.fields.outofdate = 1;
    else if (_json_str_equal(str, length, "Revoked"))
        status.fields.revoked = 1;
    else if (_json_str_equal(str, length, "ConfigurationNeeded"))
        status.fields.configuration_needed = 1;
    else if (_json_str_equal(str, length, "OutOfDateConfigurationNeeded"))
    {
        status.fields.qe_identity_out_of_date = 1;
        status.fields.configuration_needed = 1;
    }
    // Due to sgx LVI update, UpToDate tcb would be marked as SWHardeningNeeded,
    // as sgx cannot tell if enclave writer has implemented SW mitigations for
    // LVI. Set status SWHardeningNeeded as up_to_date for now to make sure
    // services for those tcbs are not affected.
    else if (_json_str_equal(str, length, "SWHardeningNeeded"))
    {
        status.fields.up_to_date = 1;
        status.fields.sw_hardening_needed = 1;
    }
    else if (_json_str_equal(str, length, "ConfigurationAndSWHardeningNeeded"))
    {
        status.fields.configuration_needed = 1;
        status.fields.sw_hardening_needed = 1;
    }

    return status;
}

/**
 * Type: tcb in TCB Info tcbLevels
 * Schema:
 * {
 *    "sgxtcbcomp01svn": uint8_t,
 *    "sgxtcbcomp02svn": uint8_t,
 *    ...
 *    "sgxtcbcomp16svn": uint8_t,
 *    "pcesvn": uint16_t
 * }
 */
static oe_result_t _read_tcb_info_tcb_level(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_info_tcb_level_t* tcb_level)
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
        OE_TRACE_VERBOSE("Reading %s", _comp_names[i]);
        OE_CHECK(_read_property_name_and_colon(_comp_names[i], itr, end));
        OE_CHECK(_read_integer(itr, end, &value));
        OE_TRACE_VERBOSE("value = %lu", value);
        OE_CHECK(_read(',', itr, end));

        if (value > OE_UCHAR_MAX)
            OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
        tcb_level->sgx_tcb_comp_svn[i] = (uint8_t)value;
    }
    OE_TRACE_VERBOSE("Reading pcesvn");
    OE_CHECK(_read_property_name_and_colon("pcesvn", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    OE_TRACE_VERBOSE("value = %lu", value);
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
static void _determine_platform_tcb_info_tcb_level(
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_tcb_info_tcb_level_t* tcb_level)
{
    // If the platform's status has already been determined, return.
    if (platform_tcb_level->status.AsUINT32 != OE_TCB_LEVEL_STATUS_UNKNOWN)
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
    platform_tcb_level->status.AsUINT32 = tcb_level->status.AsUINT32;
}

// Found matching TCB level, move itr to the end of the array.
static void _move_to_end_of_tcb_levels(const uint8_t** itr, const uint8_t* end)
{
    // Need a counter for '[', ']' to avoid early itr stop due to
    // potential '[', ']' inside array;
    uint64_t square_bracket_count = 0;
    while (*itr < end && (**itr != ']' || square_bracket_count != 0))
    {
        if (**itr == '[')
            square_bracket_count++;
        else if (**itr == ']')
            square_bracket_count--;
        (*itr)++;
    }
}

/**
 * Type: tcbLevel in TCB Info (V1)
 * Schema:
 * {
 *    "tcb" : object of type tcb
 *    "status": one of "UpToDate" or "OutOfDate" or "Revoked" or
 *              "ConfigurationNeeded"
 * }
 */
static oe_result_t _read_tcb_info_tcb_level_v1(
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_info_tcb_level_t* platform_tcb_level)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    oe_tcb_info_tcb_level_t tcb_level = {{0}};
    const uint8_t* status = NULL;
    size_t status_length = 0;

    OE_CHECK(_read('{', itr, end));

    OE_TRACE_VERBOSE("Reading tcb");
    OE_CHECK(_read_property_name_and_colon("tcb", itr, end));
    OE_CHECK(_read_tcb_info_tcb_level(itr, end, &tcb_level));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading status");
    OE_CHECK(_read_property_name_and_colon("status", itr, end));
    OE_CHECK(_read_string(itr, end, &status, &status_length));
    OE_CHECK(_trace_json_string(status, status_length));

    OE_CHECK(_read('}', itr, end));

    tcb_level.status = _parse_tcb_status(status, status_length);
    if (tcb_level.status.AsUINT32 != OE_TCB_LEVEL_STATUS_UNKNOWN)
    {
        _determine_platform_tcb_info_tcb_level(platform_tcb_level, &tcb_level);
        result = OE_OK;
    }

done:
    return result;
}

/**
 * Type: tcbLevel in TCB Info (V2)
 * Schema:
 * {
 *    "tcb" : object of type tcb (Note: QE Identity info has the same object,
 * but with different set of values). "tcbDate" : oe_datetime_t when TCB level
 * was certified not to be vulnerable. ISO 8601 standard(YYYY-MM-DDThh:mm:ssZ).
 *    "tcbStatus" : one of "UpToDate" or "OutOfDate" or "Revoked" or
 *                  "ConfigurationNeeded" or "OutOfDateConfigurationNeeded" or
 *                  "SWHardeningNeeded" or "ConfigurationAndSWHardeningNeeded"
 *    "advisoryIDs" :
 * array of strings describing vulnerabilities that this TCB level is vulnerable
 * to.  Example: ["INTEL-SA-00079", "INTEL-SA-00076"]
 * }
 */
static oe_result_t _read_tcb_info_tcb_level_v2(
    const uint8_t* info_json,
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_tcb_info_tcb_level_t* tcb_level)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* status = NULL;
    size_t status_length = 0;
    const uint8_t* date_str = NULL;
    size_t date_size = 0;

    OE_CHECK(_read('{', itr, end));

    OE_TRACE_VERBOSE("Reading tcb");
    OE_CHECK(_read_property_name_and_colon("tcb", itr, end));
    OE_CHECK(_read_tcb_info_tcb_level(itr, end, tcb_level));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading tcbDate");
    OE_CHECK(_read_property_name_and_colon("tcbDate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &tcb_level->tcb_date) != OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading tcbStatus");
    OE_CHECK(_read_property_name_and_colon("tcbStatus", itr, end));
    OE_CHECK(_read_string(itr, end, &status, &status_length));
    OE_CHECK(_trace_json_string(status, status_length));

    // Optional advisoryIDs field
    if (OE_JSON_INFO_PARSE_ERROR != _read(',', itr, end))
    {
        OE_TRACE_VERBOSE("Reading advisoryIDs");
        OE_CHECK(_read_property_name_and_colon("advisoryIDs", itr, end));
        OE_CHECK(_read('[', itr, end));

        tcb_level->advisory_ids_offset = (size_t)(*itr - info_json);
        size_t size = 0;

        while (*itr < end && **itr != ']')
        {
            (*itr)++;
            size++;
        }
        OE_CHECK(_read(']', itr, end));
        tcb_level->advisory_ids_size = size;
    }

    OE_CHECK(_read('}', itr, end));

    tcb_level->status = _parse_tcb_status(status, status_length);
    if (tcb_level->status.AsUINT32 != OE_TCB_LEVEL_STATUS_UNKNOWN)
    {
        _determine_platform_tcb_info_tcb_level(platform_tcb_level, tcb_level);
        result = OE_OK;
    }

done:
    return result;
}

/**
 * type = tcbInfo
 * V1 Schema:
 * {
 *    "version" : integer,
 *    "issueDate" : string,
 *    "nextUpdate" : string,
 *    "fmspc" : "hex string (12 nibbles)"
 *    "pceId" : "hex string (4 nibbles)"
 *    "tcbLevels" : [ objects of type oe_tcb_info_tcb_level_t ]
 * }
 *
 * V2 Schema:
 * {
 *    "version" : integer,
 *    "issueDate" : string,
 *    "nextUpdate" : string,
 *    "fmspc" : "hex string (12 nibbles)"
 *    "pceId" : "hex string (4 nibbles)"
 *    "tcbType" : integer
 *    "tcbEvaluationDataNumber" : integer
 *    "tcbLevels" : [ objects of type oe_tcb_info_tcb_level_t ]
 * }
 */
static oe_result_t _read_tcb_info(
    const uint8_t* tcb_info_json,
    const uint8_t** itr,
    const uint8_t* end,
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    uint64_t value = 0;
    const uint8_t* date_str = NULL;
    size_t date_size = 0;

    parsed_info->tcb_info_start = *itr;
    OE_CHECK(_read('{', itr, end));

    OE_TRACE_VERBOSE("Reading version");
    OE_CHECK(_read_property_name_and_colon("version", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->version = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading issueDate");
    OE_CHECK(_read_property_name_and_colon("issueDate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->issue_date) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading nextUpdate");
    OE_CHECK(_read_property_name_and_colon("nextUpdate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->next_update) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading fmspc");
    OE_CHECK(_read_property_name_and_colon("fmspc", itr, end));
    OE_CHECK(_read_hex_string(
        itr, end, parsed_info->fmspc, sizeof(parsed_info->fmspc)));
    OE_CHECK(_read(',', itr, end));

    {
        const uint8_t* old_itr = *itr;

        // read optional "pceId", if it does not exist, restore the read
        // pointers
        OE_TRACE_VERBOSE("Attempt reading optional pceId field...");

        parsed_info->pceid[0] = 0;
        parsed_info->pceid[1] = 0;
        result = _read_property_name_and_colon("pceId", itr, end);
        if (result == OE_OK)
        {
            OE_CHECK(_read_hex_string(
                itr, end, parsed_info->pceid, sizeof(parsed_info->pceid)));
            OE_CHECK(_read(',', itr, end));
        }
        else if (result == OE_JSON_INFO_PARSE_ERROR)
        {
            *itr = old_itr;
        }
    }

    if (parsed_info->version == 2)
    {
        OE_TRACE_VERBOSE("V2: Reading tcbType");
        OE_CHECK(_read_property_name_and_colon("tcbType", itr, end));
        OE_CHECK(_read_integer(itr, end, &value));
        parsed_info->tcb_type = (uint32_t)value;
        OE_CHECK(_read(',', itr, end));

        OE_TRACE_VERBOSE("V2: Reading tcbEvaluationDataNumber");
        OE_CHECK(
            _read_property_name_and_colon("tcbEvaluationDataNumber", itr, end));
        OE_CHECK(_read_integer(itr, end, &value));
        parsed_info->tcb_evaluation_data_number = (uint32_t)value;
        OE_CHECK(_read(',', itr, end));

        OE_TRACE_VERBOSE("Reading tcbLevels (V2)");
        OE_CHECK(_read_property_name_and_colon("tcbLevels", itr, end));
        OE_CHECK(_read('[', itr, end));
        while (*itr < end)
        {
            OE_CHECK(_read_tcb_info_tcb_level_v2(
                tcb_info_json,
                itr,
                end,
                platform_tcb_level,
                &parsed_info->tcb_level));

            // Optimization
            if (platform_tcb_level->status.AsUINT32 !=
                OE_TCB_LEVEL_STATUS_UNKNOWN)
            {
                // Found matching TCB level, go to the end of the array.
                _move_to_end_of_tcb_levels(itr, end);
            }

            // Read end of array or comma separator.
            if (*itr < end && **itr == ']')
                break;

            OE_CHECK(_read(',', itr, end));
        }
        OE_CHECK(_read(']', itr, end));
    }
    else if (parsed_info->version == 1)
    {
        OE_TRACE_VERBOSE("Reading tcbLevels (V1)");
        OE_CHECK(_read_property_name_and_colon("tcbLevels", itr, end));
        OE_CHECK(_read('[', itr, end));
        while (*itr < end)
        {
            OE_CHECK(_read_tcb_info_tcb_level_v1(itr, end, platform_tcb_level));
            // Read end of array or comma separator.
            if (*itr < end && **itr == ']')
                break;

            OE_CHECK(_read(',', itr, end));
        }
        OE_CHECK(_read(']', itr, end));
    }
    else
    {
        OE_RAISE_MSG(
            OE_JSON_INFO_PARSE_ERROR,
            "Unsupported TCB level info version %d",
            parsed_info->version);
    }

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
    oe_tcb_info_tcb_level_t* platform_tcb_level,
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

    // Initialize status
    platform_tcb_level->status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;

    itr = _skip_ws(itr, end);
    OE_CHECK(_read('{', &itr, end));

    OE_TRACE_VERBOSE("Reading tcbInfo");
    OE_CHECK(_read_property_name_and_colon("tcbInfo", &itr, end));
    OE_CHECK(_read_tcb_info(
        tcb_info_json, &itr, end, platform_tcb_level, parsed_info));
    OE_CHECK(_read(',', &itr, end));

    OE_TRACE_VERBOSE("Reading signature");
    OE_CHECK(_read_property_name_and_colon("signature", &itr, end));
    OE_CHECK(_read_hex_string(
        &itr, end, parsed_info->signature, sizeof(parsed_info->signature)));

    OE_CHECK(_read('}', &itr, end));

    if (itr == end)
    {
        if (platform_tcb_level->status.fields.up_to_date != 1)
        {
            for (uint32_t i = 0;
                 i < OE_COUNTOF(platform_tcb_level->sgx_tcb_comp_svn);
                 ++i)
                OE_TRACE_VERBOSE(
                    "sgx_tcb_comp_svn[%d] = 0x%x",
                    i,
                    platform_tcb_level->sgx_tcb_comp_svn[i]);
            OE_TRACE_VERBOSE("pce_svn = 0x%x", platform_tcb_level->pce_svn);
            OE_RAISE_MSG(
                OE_TCB_LEVEL_INVALID,
                "Platform TCB (%d) is not up-to-date",
                platform_tcb_level->status);
        }

        // Display any advisory IDs as warnings
        if (platform_tcb_level->advisory_ids_size > 0)
        {
            OE_TRACE_WARNING(
                "Found %d AdvisoryIDs for this tcb level.",
                platform_tcb_level->advisory_ids_size);
        }

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
 * V1 Schema:
 * {
 *    "version" : integer,
 *    "issueDate" : string,
 *    "nextUpdate" : string,
 *    "miscselect" : hex string,
 *    "miscselectMask" : hex string,
 *    "attributes" : hex string,
 *    "attributesMask" : hex string,
 *    "mrsigner" : hex string,
 *    "isvprodid" : integer,
 *    "isvsvn" : integer,
 * }
 */
static oe_result_t _read_qe_identity_info_v1(
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

    OE_TRACE_VERBOSE("Reading version");
    OE_CHECK(_read_property_name_and_colon("version", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->version = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading issueDate");
    OE_CHECK(_read_property_name_and_colon("issueDate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->issue_date) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading nextUpdate");
    OE_CHECK(_read_property_name_and_colon("nextUpdate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &parsed_info->next_update) !=
        OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading miscselect");
    OE_CHECK(_read_property_name_and_colon("miscselect", itr, end));
    OE_CHECK(
        _read_hex_string(itr, end, four_bytes_buf, sizeof(four_bytes_buf)));
    parsed_info->miscselect = read_uint32(four_bytes_buf);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading miscselectMask");
    OE_CHECK(_read_property_name_and_colon("miscselectMask", itr, end));
    OE_CHECK(
        _read_hex_string(itr, end, four_bytes_buf, sizeof(four_bytes_buf)));
    parsed_info->miscselect_mask = read_uint32(four_bytes_buf);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading attributes.flags");
    OE_CHECK(_read_property_name_and_colon("attributes", itr, end));
    OE_CHECK(_read_hex_string(
        itr, end, sixteen_bytes_buf, sizeof(sixteen_bytes_buf)));
    parsed_info->attributes.flags = read_uint64(sixteen_bytes_buf);
    parsed_info->attributes.xfrm = read_uint64(sixteen_bytes_buf + 8);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading attributesMask");
    OE_CHECK(_read_property_name_and_colon("attributesMask", itr, end));
    OE_CHECK(_read_hex_string(
        itr, end, sixteen_bytes_buf, sizeof(sixteen_bytes_buf)));
    parsed_info->attributes_flags_mask = read_uint64(sixteen_bytes_buf);
    parsed_info->attributes_xfrm_mask = read_uint64(sixteen_bytes_buf + 8);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading mrsigner");
    OE_CHECK(_read_property_name_and_colon("mrsigner", itr, end));
    OE_CHECK(_read_hex_string(
        itr, end, parsed_info->mrsigner, sizeof(parsed_info->mrsigner)));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading isvprodid");
    OE_CHECK(_read_property_name_and_colon("isvprodid", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->isvprodid = (uint16_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading isvsvn");
    OE_CHECK(_read_property_name_and_colon("isvsvn", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->isvsvn = (uint16_t)value;

    // itr is expected to point to the '}' that denotes the end of the qe
    // identity object. The signature is generated over the entire object
    // including the '}'.
    parsed_info->info_size = (size_t)(*itr - parsed_info->info_start + 1);
    OE_CHECK(_read('}', itr, end));
    OE_TRACE_VERBOSE("Done with last read");
    result = OE_OK;
done:
    OE_TRACE_VERBOSE(
        "Reading _read_qe_identity_info_v1 ended with [%s]\n",
        oe_result_str(result));
    return result;
}

/**
 * Type: tcb in QE Identity Info tcbLevels
 * Schema:
 * {
 *    "isvsvn": uint32_t
 * }
 */
static oe_result_t _read_qe_tcb(
    const uint8_t** itr,
    const uint8_t* end,
    oe_qe_identity_info_tcb_level_t* tcb_level)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    uint64_t value = 0;

    static const char* _names[] = {"isvsvn"};
    OE_STATIC_ASSERT(OE_COUNTOF(_names) == OE_COUNTOF(tcb_level->isvsvn));

    OE_CHECK(_read('{', itr, end));

    for (size_t i = 0; i < OE_COUNTOF(_names); ++i)
    {
        OE_TRACE_VERBOSE("Reading %s", _names[i]);
        OE_CHECK(_read_property_name_and_colon(_names[i], itr, end));
        OE_CHECK(_read_integer(itr, end, &value));
        OE_TRACE_VERBOSE("value = %lu", value);

        if (i != (OE_COUNTOF(_names) - 1))
            OE_CHECK(_read(',', itr, end));

        if (value > OE_UINT32_MAX)
            OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
        tcb_level->isvsvn[i] = (uint32_t)value;
    }

    OE_CHECK(_read('}', itr, end));

    result = OE_OK;
done:
    return result;
}

// Algorithm specified by Intel, reworded:
// 1. Go over the sorted collection of TCB levels in the JSON.
// 2. Choose the first tcb level for which  all of the platform's isv svn
// values are greater than or equal to corresponding values of
// the tcb level.
// 3. The status of the platform's tcb level is the status of the chosen tcb
// level.
// 4. If no tcb level was chosen, then the status of the platform is unknown.
static void _determine_platform_qe_tcb_level(
    oe_qe_identity_info_tcb_level_t* platform_tcb_level,
    oe_qe_identity_info_tcb_level_t* tcb_level)
{
    // If the platform's status has already been determined, return.
    if (platform_tcb_level->tcb_status.AsUINT32 != OE_TCB_LEVEL_STATUS_UNKNOWN)
        return;

    // Compare all of the platform's comp svn values with the corresponding
    // values in the current tcb level.
    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level->isvsvn); ++i)
    {
        if (platform_tcb_level->isvsvn[i] < tcb_level->isvsvn[i])
            return;
    }

    // If all the values of the tcb level are less than corresponding values of
    // the platform, then the platform's status is the status of the current tcb
    // level.
    platform_tcb_level->tcb_status = tcb_level->tcb_status;
}

/**
 * Type: tcbLevel in QE Identity Info (New in V2 of QE Identity Info)
 * Schema:
 * {
 *    "tcb" : object of type tcb (Note: TCB Info has the same object, but with
 *            different set of values).
 *    "tcbDate" : oe_datetime_t when TCB level was certified not to be
 * vulnerable. ISO 8601 standard(YYYY-MM-DDThh:mm:ssZ).
 *    "tcbStatus" : one of "UpToDate" or "OutOfDate" or "Revoked" or
 * "ConfigurationNeeded" or "OutOfDateConfigurationNeeded" or
 * "SWHardeningNeeded" or "ConfigurationAndSWHardeningNeeded"
 *    "advisoryIDs" : array of strings describing vulnerabilities that this TCB
 * level is vulnerable to.  Example:
 * ["INTEL-SA-00079", "INTEL-SA-00076"]
 * }
 */
static oe_result_t _read_qe_tcb_level(
    const uint8_t* info_json,
    const uint8_t** itr,
    const uint8_t* end,
    oe_qe_identity_info_tcb_level_t* platform_qe_tcb_level,
    oe_qe_identity_info_tcb_level_t* tcb_level)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* status = NULL;
    size_t status_length = 0;
    const uint8_t* date_str = NULL;
    size_t date_size = 0;

    memset(tcb_level, 0, sizeof(oe_qe_identity_info_tcb_level_t));

    OE_CHECK(_read('{', itr, end));

    OE_TRACE_VERBOSE("Reading QE Identity tcb");
    OE_CHECK(_read_property_name_and_colon("tcb", itr, end));
    OE_CHECK(_read_qe_tcb(itr, end, tcb_level));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading tcbDate");
    OE_CHECK(_read_property_name_and_colon("tcbDate", itr, end));
    OE_CHECK(_read_string(itr, end, &date_str, &date_size));
    if (oe_datetime_from_string(
            (const char*)date_str, date_size, &tcb_level->tcb_date) != OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading tcbStatus");
    OE_CHECK(_read_property_name_and_colon("tcbStatus", itr, end));
    OE_CHECK(_read_string(itr, end, &status, &status_length));
    OE_CHECK(_trace_json_string(status, status_length));

    // Optional advisoryIDs field
    if (OE_JSON_INFO_PARSE_ERROR != _read(',', itr, end))
    {
        OE_TRACE_VERBOSE("Reading advisoryIDs");
        OE_CHECK(_read_property_name_and_colon("advisoryIDs", itr, end));
        OE_CHECK(_read('[', itr, end));

        tcb_level->advisory_ids_offset = (size_t)(*itr - info_json);
        size_t size = 0;

        while (*itr < end && **itr != ']')
        {
            (*itr)++;
            size++;
        }
        OE_CHECK(_read(']', itr, end));
        tcb_level->advisory_ids_size = size;
    }

    OE_CHECK(_read('}', itr, end));

    tcb_level->tcb_status = _parse_tcb_status(status, status_length);
    if (tcb_level->tcb_status.AsUINT32 != OE_TCB_LEVEL_STATUS_UNKNOWN)
    {
        _determine_platform_qe_tcb_level(platform_qe_tcb_level, tcb_level);
        result = OE_OK;
    }

done:
    return result;
}

/*!
 * type = enclaveIdentity
 * V2 Schema:
 * {
 *    "id" : string ("QE" | "QVE")
 *    "version" : integer,
 *    "issueDate" : string,
 *    "nextUpdate" : string,
 *    "tcbEvaluationDataNumber" : integer
 *    "miscselect" : hex string,
 *    "miscselectMask" : hex string,
 *    "attributes" : hex string,
 *    "attributesMask" : hex string,
 *    "mrsigner" : hex string,
 *    "isvprodid" : integer,
 *    "tcbLevels" : [ objects of type oe_qe_identity_info_tcb_level_t ]
 * }
 */
static oe_result_t _read_qe_identity_info_v2(
    const uint8_t* info_json,
    const uint8_t** itr,
    const uint8_t* end,
    oe_qe_identity_info_tcb_level_t* platform_tcb_level,
    oe_parsed_qe_identity_info_t* parsed_info)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    uint64_t value = 0;
    const uint8_t* str = NULL;
    size_t size = 0;
    uint8_t four_bytes_buf[4];
    uint8_t sixteen_bytes_buf[16];

    if (platform_tcb_level == NULL)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "QE identity info v2 requires platform tcb level.",
            NULL);

    // Initialize status.
    platform_tcb_level->tcb_status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;

    parsed_info->info_start = *itr;
    OE_CHECK(_read('{', itr, end));

    OE_TRACE_VERBOSE("Reading id");
    OE_CHECK(_read_property_name_and_colon("id", itr, end));
    OE_CHECK(_read_string(itr, end, &str, &size));
    if (_json_str_equal(str, size, "QE"))
        parsed_info->id = QE_IDENTITY_ID_QE;
    else if (_json_str_equal(str, size, "QVE"))
        parsed_info->id = QE_IDENTITY_ID_QVE;
    else
        OE_RAISE_MSG(OE_JSON_INFO_PARSE_ERROR, "Invalid id %s", str);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading version");
    OE_CHECK(_read_property_name_and_colon("version", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->version = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading issueDate");
    OE_CHECK(_read_property_name_and_colon("issueDate", itr, end));
    OE_CHECK(_read_string(itr, end, &str, &size));
    if (oe_datetime_from_string(
            (const char*)str, size, &parsed_info->issue_date) != OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading nextUpdate");
    OE_CHECK(_read_property_name_and_colon("nextUpdate", itr, end));
    OE_CHECK(_read_string(itr, end, &str, &size));
    if (oe_datetime_from_string(
            (const char*)str, size, &parsed_info->next_update) != OE_OK)
        OE_RAISE(OE_JSON_INFO_PARSE_ERROR);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading tcbEvaluationDataNumber");
    OE_CHECK(
        _read_property_name_and_colon("tcbEvaluationDataNumber", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->tcb_evaluation_data_number = (uint32_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading miscselect");
    OE_CHECK(_read_property_name_and_colon("miscselect", itr, end));
    OE_CHECK(
        _read_hex_string(itr, end, four_bytes_buf, sizeof(four_bytes_buf)));
    parsed_info->miscselect = read_uint32(four_bytes_buf);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading miscselectMask");
    OE_CHECK(_read_property_name_and_colon("miscselectMask", itr, end));
    OE_CHECK(
        _read_hex_string(itr, end, four_bytes_buf, sizeof(four_bytes_buf)));
    parsed_info->miscselect_mask = read_uint32(four_bytes_buf);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading attributes.flags");
    OE_CHECK(_read_property_name_and_colon("attributes", itr, end));
    OE_CHECK(_read_hex_string(
        itr, end, sixteen_bytes_buf, sizeof(sixteen_bytes_buf)));
    parsed_info->attributes.flags = read_uint64(sixteen_bytes_buf);
    parsed_info->attributes.xfrm = read_uint64(sixteen_bytes_buf + 8);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading attributesMask");
    OE_CHECK(_read_property_name_and_colon("attributesMask", itr, end));
    OE_CHECK(_read_hex_string(
        itr, end, sixteen_bytes_buf, sizeof(sixteen_bytes_buf)));
    parsed_info->attributes_flags_mask = read_uint64(sixteen_bytes_buf);
    parsed_info->attributes_xfrm_mask = read_uint64(sixteen_bytes_buf + 8);
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading mrsigner");
    OE_CHECK(_read_property_name_and_colon("mrsigner", itr, end));
    OE_CHECK(_read_hex_string(
        itr, end, parsed_info->mrsigner, sizeof(parsed_info->mrsigner)));
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading isvprodid");
    OE_CHECK(_read_property_name_and_colon("isvprodid", itr, end));
    OE_CHECK(_read_integer(itr, end, &value));
    parsed_info->isvprodid = (uint16_t)value;
    OE_CHECK(_read(',', itr, end));

    OE_TRACE_VERBOSE("Reading tcbLevels");
    OE_CHECK(_read_property_name_and_colon("tcbLevels", itr, end));
    OE_CHECK(_read('[', itr, end));
    while (*itr < end)
    {
        OE_CHECK(_read_qe_tcb_level(
            info_json, itr, end, platform_tcb_level, &parsed_info->tcb_level));

        // Optimization
        if (platform_tcb_level->tcb_status.AsUINT32 !=
            OE_TCB_LEVEL_STATUS_UNKNOWN)
        {
            // Found matching TCB level, go to the end of the array.
            _move_to_end_of_tcb_levels(itr, end);
        }

        // Read end of array or comma separator.
        if (*itr < end && **itr == ']')
            break;

        OE_CHECK(_read(',', itr, end));
    }
    OE_CHECK(_read(']', itr, end));

    // Synchronize legacy V1 field.
    parsed_info->isvsvn = (uint16_t)parsed_info->tcb_level.isvsvn[0];

    // itr is expected to point to the '}' that denotes the end of the qe
    // identity object. The signature is generated over the entire object
    // including the '}'.
    parsed_info->info_size = (size_t)(*itr - parsed_info->info_start + 1);
    OE_CHECK(_read('}', itr, end));
    OE_TRACE_VERBOSE("Done with last read");
    result = OE_OK;
done:
    OE_TRACE_VERBOSE(
        "Reading %s ended with [%s]\n", __FUNCTION__, oe_result_str(result));
    return result;
}

/**
 * type = qe_identity_info
 *
 * Schema V1:
 * {
 *    "qeIdentity" : object of type qe_identity,
 *    "signature" : "hex string"
 * }
 *
 * Schema V2:
 * {
 *    "enclaveIdentity" : object of type enclaveIdentity,
 *    "signature" : "hex string"
 * }
 */
oe_result_t oe_parse_qe_identity_info_json(
    const uint8_t* info_json,
    size_t info_json_size,
    oe_qe_identity_info_tcb_level_t* platform_tcb_level,
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

    if (OE_JSON_INFO_PARSE_ERROR !=
        _read_property_name_and_colon("enclaveIdentity", &itr, end))
    {
        OE_TRACE_VERBOSE("Reading enclaveIdentity");
        OE_CHECK(_read_qe_identity_info_v2(
            info_json, &itr, end, platform_tcb_level, parsed_info));
        OE_CHECK(_read(',', &itr, end));
    }
    else
    {
        OE_TRACE_VERBOSE("Reading qeIdentity");
        OE_CHECK(_read_property_name_and_colon("qeIdentity", &itr, end));
        OE_CHECK(_read_qe_identity_info_v1(&itr, end, parsed_info));
        OE_CHECK(_read(',', &itr, end));
    }

    OE_TRACE_VERBOSE("Reading signature");
    OE_CHECK(_read_property_name_and_colon("signature", &itr, end));
    OE_CHECK(_read_hex_string(
        &itr, end, parsed_info->signature, sizeof(parsed_info->signature)));
    OE_CHECK(_read('}', &itr, end));

    if (itr == end)
    {
        if (parsed_info->version == 2 &&
            platform_tcb_level->tcb_status.fields.up_to_date != 1)
        {
            for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level->isvsvn);
                 ++i)
                OE_TRACE_VERBOSE(
                    "isvsvn[%d] = 0x%x", i, platform_tcb_level->isvsvn[i]);
            OE_RAISE_MSG(
                OE_TCB_LEVEL_INVALID,
                "QE Identity Information (%d) is not up-to-date",
                platform_tcb_level->tcb_status.AsUINT32);
        }

        // Display any advisory IDs as warnings
        if (parsed_info->tcb_level.advisory_ids_size > 0)
        {
            OE_TRACE_WARNING(
                "Found %d AdvisoryIDs for this tcb level.",
                parsed_info->tcb_level.advisory_ids_size);
        }
        result = OE_OK;
    }

done:
    OE_TRACE_VERBOSE(
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

    OE_CHECK(oe_ecdsa_signature_write_der(
        asn1Signature,
        &asn1SignatureSize,
        signature->r,
        sizeof(signature->r),
        signature->s,
        sizeof(signature->s)));

    OE_CHECK(oe_ec_public_key_verify(
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

    OE_CHECK(_ecdsa_verify(
        &tcb_signing_key, tcb_info_start, tcb_info_size, signature));

    // Ensure that the root certificate matches root of trust.
    OE_CHECK(oe_ec_public_key_read_pem(
        &trusted_root_key,
        (const uint8_t*)_trusted_root_key_pem,
        oe_strlen(_trusted_root_key_pem) + 1));

    OE_CHECK(oe_ec_public_key_equal(
        &trusted_root_key, &tcb_root_key, &root_of_trust_match));

    if (!root_of_trust_match)
    {
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    OE_TRACE_VERBOSE("tcb info ecdsa attestation succeeded");

    result = OE_OK;
done:
    oe_ec_public_key_free(&trusted_root_key);
    oe_ec_public_key_free(&tcb_signing_key);
    oe_ec_public_key_free(&tcb_root_key);

    oe_cert_free(&leaf_cert);
    oe_cert_free(&root_cert);

    return result;
}

oe_result_t oe_parse_advisoryids_json(
    const uint8_t* json,
    size_t json_size,
    const uint8_t** id_array,
    size_t id_array_size,
    size_t* id_sizes_array,
    size_t id_sizes_size,
    size_t* num_ids)
{
    oe_result_t result = OE_JSON_INFO_PARSE_ERROR;
    const uint8_t* itr = json;
    const uint8_t* end = json + json_size;
    size_t count = 0;

    if (json == NULL || json_size == 0 || id_array == NULL || num_ids == NULL ||
        (id_array_size != id_sizes_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    *num_ids = 0;

    while (itr < end && count < id_array_size)
    {
        OE_CHECK(
            _read_string(&itr, end, &id_array[count], &id_sizes_array[count]));
        count += 1;

        if (itr < end)
            OE_CHECK(_read(',', &itr, end));
    }

    *num_ids = count;
    result = OE_OK;
done:

    return result;
}