// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/json.h>

OE_EXTERNC_BEGIN

typedef struct _OE_JsonParser
{
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
        c == '\r');
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
    const uint8_t* end)
{
    if (!p->parseFailed)
    {
        p->errorMsg = msg;
        if (p->interface.handleError)
            p->interface.handleError(p->data, msg);
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
    itr = _SkipWS(itr, end);

    if (itr == end)
        return _ReportError(p, "Unexpected end of input.", end);

    if (*itr != ch)
        return _ReportError(p, "Expected char not found.", end);

    // skip character and any whitespace trailing it
    _SkipWS(++itr, end);
    return itr;
}

static const uint8_t* _ReadQuotedString(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (itr == end || (*itr != '"' && *itr != '\''))
    {
        return _ReportError(p, "Expecting a '\"'.", end);
    }

    uint8_t quote = *itr++;

    while (itr != end && *itr != quote)
    {
        if (*itr == '\\')
        {
            if (++itr + 1 == end)
                return _ReportError(p, "Unclosed string", end);
        }
        ++itr;
    }

    return _Expect(p, quote, itr, end);
}

static const uint8_t* _ReadNumber(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    while (itr != end &&
           (_IsAlnum(*itr) || *itr == '+' || *itr == '-' || *itr == '.'))
    {
        ++itr;
    }

    return _SkipWS(itr, end);
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

    // read each item.
    while (itr != end && *itr != ']')
    {
        itr = _Read(p, itr, end);

        // each item is separated by a comma.
        if (itr != end && *itr == ',')
            ++itr;
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

    // Skip whitespace before first property.
    itr = _SkipWS(itr, end);

    // read properties of the object.
    while (itr != end && *itr != '}')
    {
        itr = _ReadProperty(p, itr, end);

        // each property is separated by a comma
        if (itr != end && *itr == ',')
            ++itr;
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
        return _ReportError(p, "Unexpected end of input.", end);

    if (_IsDigit(*itr))
    {
        itr = _ReadNumber(p, itr, end);
        if (!p->parseFailed && p->interface.number)
            if (p->interface.number(p->data, start, itr - start) != OE_OK)
                return end;
    }
    else if (*itr == '"' || *itr == '\'')
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
