// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/json.h>

OE_EXTERNC_BEGIN

typedef struct _OE_JsonParser
{
    const uint8_t* jsonString;
    uint8_t parseFailed;
    void* data;
    OE_JsonParserCallbackInterface interface;
    const char* errorMsg;
} OE_JsonParser;

// Character classification primitives implemented here
// to avoid dependency on libc.

OE_INLINE uint8_t _IsAlpha(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

OE_INLINE uint8_t _IsDigit(uint8_t c)
{
    return (c >= '0' && c <= '9');
}

OE_INLINE uint8_t _IsAlnum(uint8_t c)
{
    return _IsAlpha(c) || _IsDigit(c);
}

OE_INLINE uint8_t _IsSpace(uint8_t c)
{
    return (
        c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' ||
        c == '\r' || c == '\0');
}

// Skip white space
static const uint8_t* _SkipWS(const uint8_t* itr, const uint8_t* end)
{
    while (itr != end && _IsSpace(*itr))
        ++itr;
    return itr;
}

static const uint8_t* _ReportError(
    OE_JsonParser* p,
    const char* msg,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (!p->parseFailed)
    {
        p->errorMsg = msg;
        if (p->interface.handleError)
            p->interface.handleError(p->data, itr - p->jsonString, msg);
        p->parseFailed = 1;
    }
    return end;
}

// Expect a given character
static const uint8_t* _Expect(
    OE_JsonParser* p,
    uint8_t ch,
    const uint8_t* itr,
    const uint8_t* end)
{
    // Skip leading white space.
    itr = _SkipWS(itr, end);

    if (itr == end)
        return _ReportError(p, "Unexpected end of input.", itr, end);

    if (*itr != ch)
        return _ReportError(p, "Expected char not found.", itr, end);

    // Skip character and trailing white space.
    return _SkipWS(++itr, end);
}

static const uint8_t* _ReadQuotedString(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (itr == end || *itr != '"')
    {
        return _ReportError(p, "Expecting a '\"'.", itr, end);
    }

    uint8_t quote = *itr++;

    while (itr != end && *itr != quote)
    {
        if (*itr == '\\')
        {
            // Skip \.
            ++itr;
            if (itr == end)
                return _ReportError(p, "Unclosed string", itr, end);
            // Fall through to skip the character following \.
        }
        ++itr;
    }

    if (itr == end)
        return _ReportError(p, "Unclosed string", itr, end);

    // Skip ending quote.
    return itr + 1;
}

static const uint8_t* _ReadNumber(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (itr == end)
        return _ReportError(p, "Unexpected eof", itr, end);

    // Grammer:
    //    number = {-} decimal_part {fractional_part} {exponent_part}
    //    decimal_part = 0 | ([1..9] [0..9]*)
    //    fractional_part = . [0..9]+
    //    exponent_part {[eE]{[+-]}[0..9]+}
    //    where {x} means x is optional
    //          * means zero or more
    //          + means one or more
    //          [values] means one of the items in values.
    // Number can start with a minus.
    if (*itr == '-')
        ++itr;

    if (itr == end || !_IsDigit(*itr))
        return _ReportError(p, "Ill formed number", itr, end);

    // Read decimal part
    if (*itr == '0')
    {
        ++itr;
    }
    else
    {
        // *itr >= 1 && *itr <= '9'
        ++itr;
        while (itr != end && _IsDigit(*itr))
            ++itr;
    }

    // Read optional fractional part.
    if (itr != end && *itr == '.')
    {
        ++itr;
        if (itr == end || !_IsDigit(*itr))
            return _ReportError(p, "Expecting digit to follow .", itr, end);

        while (itr != end && _IsDigit(*itr))
            ++itr;
    }

    // Read optional exponent part.
    if (itr != end && (*itr == 'e' || *itr == 'E'))
    {
        ++itr;
        // Read optional exponent sign.
        if (itr != end && (*itr == '+' || *itr == '-'))
            ++itr;

        if (itr == end || !_IsDigit(*itr))
            return _ReportError(p, "Ill formed exponent", itr, end);

        // Read exponent digits.
        while (itr != end && _IsDigit(*itr))
            ++itr;
    }

    return itr;
}

static const uint8_t* _ReadNull(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (end - itr >= 4)
    {
        if (itr[0] == 'n' && itr[1] == 'u' && itr[2] == 'l' && itr[3] == 'l' &&
            (itr + 4 == end || !_IsAlnum(itr[4])))
        {
            if (p->interface.null)
                if (p->interface.null(p->data) != OE_OK)
                    return end;
            return itr + 4;
        }
    }

    return _ReportError(p, "Unexpected character", itr, end);
}

static const uint8_t* _ReadBoolean(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if ((end - itr) >= 4 && itr[0] == 't')
    {
        if (itr[1] == 'r' && itr[2] == 'u' && itr[3] == 'e' &&
            (itr + 4 == end || !_IsAlnum(itr[4])))
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
            (itr + 5 == end || !_IsAlnum(itr[5])))
        {
            if (p->interface.boolean)
                if (p->interface.boolean(p->data, 0) != OE_OK)
                    return end;
            return itr + 5;
        }
    }

    return _ReportError(p, "Unexpected character", itr, end);
}

static const uint8_t* _Read(
    OE_JsonParser* v,
    const uint8_t* itr,
    const uint8_t* end);

// Read array object.
// '['
//     elem ','
//     elem ','
//      ...
// ']'
static const uint8_t* _ReadArray(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    itr = _Expect(p, '[', itr, end);

    if (!p->parseFailed && p->interface.beginArray)
        if (p->interface.beginArray(p->data) != OE_OK)
            return end;

    if (itr != end && *itr != ']')
    {
        // Non empty array.
        // Read each item.
        while (itr != end)
        {
            itr = _SkipWS(_Read(p, itr, end), end);
            if (itr != end)
            {
                if (*itr == ']')
                    break;

                // Items must be separated by comma.
                itr = _Expect(p, ',', itr, end);
            }
        }
    }

    itr = _Expect(p, ']', itr, end);

    if (!p->parseFailed && p->interface.endArray)
        if (p->interface.endArray(p->data) != OE_OK)
            return end;

    return itr;
}

static const uint8_t* _ReadObject(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end);

// Read a property.
// Each property is expressed as:
// [ws] "property-name"  [ws]  :   [ws] property-value [ws]
// (1)       (2)         (3)  (4)  (5)       (6)       (7)
static const uint8_t* _ReadProperty(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    const uint8_t* prop_name = NULL;
    // (1) =>
    itr = _SkipWS(itr, end);

    // (2) =>
    prop_name = itr + 1; // skip starting quote
    itr = _ReadQuotedString(p, itr, end);

    if (!p->parseFailed && p->interface.propertyName)
        if (p->interface.propertyName(
                p->data, prop_name, itr - prop_name - 1) != OE_OK)
            return end;

    // (3) =>
    itr = _SkipWS(itr, end);

    // (4) =>
    itr = _Expect(p, ':', itr, end);

    // (5) =>
    itr = _SkipWS(itr, end);

    // (6) =>
    itr = _Read(p, itr, end);

    // (7) =>
    return _SkipWS(itr, end);
}

// Read a record object.
// '{'
//      property ','
//      property ','
//      ...
// '}'
static const uint8_t* _ReadObject(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    itr = _Expect(p, '{', itr, end);

    if (!p->parseFailed && p->interface.beginObject)
        if (p->interface.beginObject(p->data) != OE_OK)
            return end;

    if (itr != end && *itr != '}')
    {
        // Non empty object.
        while (itr != end)
        {
            itr = _SkipWS(_ReadProperty(p, itr, end), end);
            if (itr != end)
            {
                if (*itr == '}')
                    break;
                // Properties are separated by comma.
                itr = _Expect(p, ',', itr, end);
            }
        }
    }

    itr = _Expect(p, '}', itr, end);

    if (!p->parseFailed && p->interface.endObject)
        if (p->interface.endObject(p->data) != OE_OK)
            return end;

    return itr;
}

static const uint8_t* _Read(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    const uint8_t* start = NULL;

    // skip leading whitespace
    itr = _SkipWS(itr, end);
    start = itr;

    if (itr == end)
        return _ReportError(p, "Unexpected end of input.", itr, end);

    if (_IsDigit(*itr) || *itr == '-')
    {
        itr = _ReadNumber(p, itr, end);
        if (!p->parseFailed && p->interface.number)
            if (p->interface.number(p->data, start, itr - start) != OE_OK)
                return end;
    }
    else if (*itr == '"')
    {
        start = itr + 1;
        itr = _ReadQuotedString(p, itr, end);
        if (!p->parseFailed && p->interface.string)
            if (p->interface.string(p->data, start, itr - start - 1) != OE_OK)
                return end;
    }
    else if (*itr == '[')
    {
        itr = _ReadArray(p, itr, end);
    }
    else if (*itr == 'n')
    {
        itr = _ReadNull(p, itr, end);
    }
    else if (*itr == 't' || *itr == 'f')
    {
        itr = _ReadBoolean(p, itr, end);
    }
    else
    {
        itr = _ReadObject(p, itr, end);
    }

    return _SkipWS(itr, end);
}

oe_result_t OE_ParseJson(
    const uint8_t* json,
    uint32_t jsonLength,

    void* callbackData,
    const OE_JsonParserCallbackInterface* interface)
{
    OE_JsonParser p = {0};
    p.jsonString = json;
    const uint8_t* itr = json;
    const uint8_t* end = json + jsonLength;

    p.parseFailed = 0;
    p.data = callbackData;
    if (interface)
        p.interface = *interface;

    itr = _Read(&p, itr, end);
    if (itr == end && !p.parseFailed)
        return OE_OK;
    return OE_FAILURE;
}

OE_EXTERNC_END
