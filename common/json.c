// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/json.h>

OE_EXTERNC_BEGIN

typedef struct _oe_json_parser
{
    const uint8_t* json_string;
    uint8_t parse_failed;
    void* data;
    oe_json_parser_callback_interface interface;
    const char* error_message;
} oe_json_parser_t;

// Character classification primitives implemented here
// to avoid dependency on libc.

OE_INLINE uint8_t _is_alpha(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

OE_INLINE uint8_t _is_digit(uint8_t c)
{
    return (c >= '0' && c <= '9');
}

OE_INLINE uint8_t _is_alnum(uint8_t c)
{
    return _is_alpha(c) || _is_digit(c);
}

OE_INLINE uint8_t _is_space(uint8_t c)
{
    return (
        c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' ||
        c == '\r' || c == '\0');
}

OE_INLINE uint8_t _is_hex(uint8_t c)
{
    return _is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Skip white space
static const uint8_t* _skip_ws(const uint8_t* itr, const uint8_t* end)
{
    while (itr != end && _is_space(*itr))
        ++itr;
    return itr;
}

static const uint8_t* _report_error(
    oe_json_parser_t* p,
    const char* msg,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (!p->parse_failed)
    {
        p->error_message = msg;
        if (p->interface.handle_error)
            p->interface.handle_error(p->data, itr - p->json_string, msg);
        p->parse_failed = 1;
    }
    return end;
}

// Expect a given character
static const uint8_t* _expect(
    oe_json_parser_t* p,
    uint8_t ch,
    const uint8_t* itr,
    const uint8_t* end)
{
    // Skip leading white space.
    itr = _skip_ws(itr, end);

    if (itr == end)
        return _report_error(p, "Unexpected end of input.", itr, end);

    if (*itr != ch)
        return _report_error(p, "Expected char not found.", itr, end);

    // Skip character and trailing white space.
    return _skip_ws(++itr, end);
}

static const uint8_t* _read_quoted_string(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (itr == end || *itr != '"')
    {
        return _report_error(p, "Expecting a '\"'.", itr, end);
    }

    uint8_t quote = *itr++;

    while (itr != end && *itr != quote)
    {
        if (*itr == '\\')
        {
            // Parse escape sequence.
            if (++itr == end)
                return _report_error(p, "Illegal escape sequence", itr, end);

            switch (*itr)
            {
                case '"':
                case '\\':
                case '/':
                case 'b':
                case 'f':
                case 'n':
                case 'r':
                case 't':
                    ++itr;
                    continue;
                case 'u':
                    // Expect 4 hexadecimal digits.
                    ++itr;
                    if (end - itr >= 4 && _is_hex(itr[0]) && _is_hex(itr[1]) &&
                        _is_hex(itr[2]) && _is_hex(itr[3]))
                    {
                        itr += 4;
                        continue;
                    }
                default:
                    _report_error(p, "Illegal escape sequence", itr, end);
            }
        }
        else
        {
            ++itr;
        }
    }

    if (itr == end)
        return _report_error(p, "Unclosed string", itr, end);

    // Skip ending quote.
    return itr + 1;
}

static const uint8_t* _read_number(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (itr == end)
        return _report_error(p, "Unexpected eof", itr, end);

    // Grammer:
    //    number = {-} decimal_part {fractional_part} {exponent_part}
    //    decimal_part = 0 | ([1..9] [0..9]*)
    //    fractional_part = . [0..9]+
    //    exponent_part  = [eE]{[+-]}[0..9]+
    //    where {x} means x is optional
    //          * means zero or more
    //          + means one or more
    //          [values] means one of the items in values.
    // Number can start with a minus.
    if (*itr == '-')
        ++itr;

    if (itr == end || !_is_digit(*itr))
        return _report_error(p, "Ill formed number", itr, end);

    // Read decimal part
    if (*itr == '0')
    {
        ++itr;
    }
    else
    {
        // *itr >= 1 && *itr <= '9'
        ++itr;
        while (itr != end && _is_digit(*itr))
            ++itr;
    }

    // Read optional fractional part.
    if (itr != end && *itr == '.')
    {
        ++itr;
        if (itr == end || !_is_digit(*itr))
            return _report_error(p, "Expecting digit to follow .", itr, end);

        while (itr != end && _is_digit(*itr))
            ++itr;
    }

    // Read optional exponent part.
    if (itr != end && (*itr == 'e' || *itr == 'E'))
    {
        ++itr;
        // Read optional exponent sign.
        if (itr != end && (*itr == '+' || *itr == '-'))
            ++itr;

        if (itr == end || !_is_digit(*itr))
            return _report_error(p, "Ill formed exponent", itr, end);

        // Read exponent digits.
        while (itr != end && _is_digit(*itr))
            ++itr;
    }

    return itr;
}

static const uint8_t* _read_null(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (end - itr >= 4)
    {
        if (itr[0] == 'n' && itr[1] == 'u' && itr[2] == 'l' && itr[3] == 'l' &&
            (itr + 4 == end || !_is_alnum(itr[4])))
        {
            if (p->interface.null)
                if (p->interface.null(p->data) != OE_OK)
                    return end;
            return itr + 4;
        }
    }

    return _report_error(p, "Unexpected character", itr, end);
}

static const uint8_t* _read_boolean(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if ((end - itr) >= 4 && itr[0] == 't')
    {
        if (itr[1] == 'r' && itr[2] == 'u' && itr[3] == 'e' &&
            (itr + 4 == end || !_is_alnum(itr[4])))
        {
            if (p->interface.boolean)
                if (p->interface.boolean(p->data, 1) != OE_OK)
                    return end;
            return itr + 4;
        }
    }
    if ((end - itr) >= 5 && itr[0] == 'f')
    {
        if (itr[1] == 'a' && itr[2] == 'l' && itr[3] == 's' && itr[4] == 'e' &&
            (itr + 5 == end || !_is_alnum(itr[5])))
        {
            if (p->interface.boolean)
                if (p->interface.boolean(p->data, 0) != OE_OK)
                    return end;
            return itr + 5;
        }
    }

    return _report_error(p, "Unexpected character", itr, end);
}

static const uint8_t* _read(
    oe_json_parser_t* v,
    const uint8_t* itr,
    const uint8_t* end);

// Read array object.
// '['
//     elem ','
//     elem ','
//      ...
// ']'
static const uint8_t* _read_array(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    itr = _skip_ws(itr, end);
    if (itr == end || *itr != '[')
        return _report_error(p, "Expecting '['", itr, end);

    if (!p->parse_failed && p->interface.begin_array)
        if (p->interface.begin_array(p->data, itr) != OE_OK)
            return end;

    // Skip '[' and trailing spaces.
    itr = _skip_ws(++itr, end);

    if (itr != end && *itr != ']')
    {
        // Non empty array.
        // Read each item.
        while (itr != end)
        {
            itr = _skip_ws(_read(p, itr, end), end);
            if (itr != end)
            {
                if (*itr == ']')
                    break;

                // Items must be separated by comma.
                itr = _expect(p, ',', itr, end);
            }
        }
    }

    if (itr == end || *itr != ']')
        return _report_error(p, "Expecting ']'", itr, end);

    if (!p->parse_failed && p->interface.end_array)
        if (p->interface.end_array(p->data, itr) != OE_OK)
            return end;

    // Skip ']' and trailing spaces.
    return _skip_ws(++itr, end);
}

static const uint8_t* _read_object(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end);

// Read a property.
// Each property is expressed as:
// [ws] "property-name"  [ws]  :   [ws] property-value [ws]
// (1)       (2)         (3)  (4)  (5)       (6)       (7)
static const uint8_t* _read_property(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    const uint8_t* prop_name = NULL;
    // (1) =>
    itr = _skip_ws(itr, end);

    // (2) =>
    prop_name = itr + 1; // skip starting quote
    itr = _read_quoted_string(p, itr, end);

    if (!p->parse_failed && p->interface.property_name)
        if (p->interface.property_name(
                p->data, prop_name, itr - prop_name - 1) != OE_OK)
            return end;

    // (3) =>
    itr = _skip_ws(itr, end);

    // (4) =>
    itr = _expect(p, ':', itr, end);

    // (5) =>
    itr = _skip_ws(itr, end);

    // (6) =>
    itr = _read(p, itr, end);

    // (7) =>
    return _skip_ws(itr, end);
}

// Read a record object.
// '{'
//      property ','
//      property ','
//      ...
// '}'
static const uint8_t* _read_object(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    itr = _skip_ws(itr, end);

    if (itr == end || *itr != '{')
        return _report_error(p, "Expecting '{'", itr, end);

    if (!p->parse_failed && p->interface.begin_object)
        if (p->interface.begin_object(p->data, itr) != OE_OK)
            return end;

    // Skip '{' and trailing spaces.
    itr = _skip_ws(++itr, end);

    if (itr != end && *itr != '}')
    {
        // Non empty object.
        while (itr != end)
        {
            itr = _skip_ws(_read_property(p, itr, end), end);
            if (itr != end)
            {
                if (*itr == '}')
                    break;
                // Properties are separated by comma.
                itr = _expect(p, ',', itr, end);
            }
        }
    }

    if (itr == end || *itr != '}')
        return _report_error(p, "Expecting '}'", itr, end);

    if (!p->parse_failed && p->interface.end_object)
        if (p->interface.end_object(p->data, itr) != OE_OK)
            return end;

    // Skip '}' and trailing spaces.
    return _skip_ws(++itr, end);
}

static const uint8_t* _read(
    oe_json_parser_t* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    const uint8_t* start = NULL;

    // skip leading whitespace
    itr = _skip_ws(itr, end);
    start = itr;

    if (itr == end)
        return _report_error(p, "Unexpected end of input.", itr, end);

    if (_is_digit(*itr) || *itr == '-')
    {
        itr = _read_number(p, itr, end);
        if (!p->parse_failed && p->interface.number)
            if (p->interface.number(p->data, start, itr - start) != OE_OK)
                return end;
    }
    else if (*itr == '"')
    {
        start = itr + 1;
        itr = _read_quoted_string(p, itr, end);
        if (!p->parse_failed && p->interface.string)
            if (p->interface.string(p->data, start, itr - start - 1) != OE_OK)
                return end;
    }
    else if (*itr == '[')
    {
        itr = _read_array(p, itr, end);
    }
    else if (*itr == 'n')
    {
        itr = _read_null(p, itr, end);
    }
    else if (*itr == 't' || *itr == 'f')
    {
        itr = _read_boolean(p, itr, end);
    }
    else
    {
        itr = _read_object(p, itr, end);
    }

    return _skip_ws(itr, end);
}

oe_result_t oe_parse_json(
    const uint8_t* json,
    uint32_t json_length,
    void* callback_data,
    const oe_json_parser_callback_interface* interface)
{
    oe_json_parser_t p = {0};
    p.json_string = json;
    const uint8_t* itr = json;
    const uint8_t* end = json + json_length;

    p.parse_failed = 0;
    p.data = callback_data;
    if (interface)
        p.interface = *interface;

    itr = _read(&p, itr, end);
    if (itr == end && !p.parse_failed)
        return OE_OK;
    return OE_FAILURE;
}

OE_EXTERNC_END
