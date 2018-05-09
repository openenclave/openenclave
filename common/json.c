// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/bits/json.h>

OE_EXTERNC_BEGIN

typedef struct _OE_JsonParser
{
    uint8_t parseFailed;
    void* data;
    OE_JsonParserCallbackInterface interface;
    const char* errorMsg;
} OE_JsonParser;

uint8_t isAlnum(uint8_t c)
{
    return (((unsigned)c | 32) - 'a' < 26) || ((unsigned)c - '0' < 10);
}

OE_INLINE uint8_t isSpace(uint8_t c)
{
    return c == ' ' || (unsigned)c - '\t' < 5;
}

// Skip white space
static const uint8_t* skipWS(const uint8_t* itr, const uint8_t* end)
{
    while (itr != end && isSpace(*itr))
        ++itr;
    return itr;
}

static const uint8_t* reportError(
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
static const uint8_t* expect(
    OE_JsonParser* p,
    uint8_t ch,
    const uint8_t* itr,
    const uint8_t* end)
{
    itr = skipWS(itr, end);

    if (itr == end)
        return reportError(p, "Unexpected end of input.", end);

    if (*itr != ch)
        return reportError(p, "Expected char not found.", end);

    // skip character and any whitespace trailing it
    skipWS(++itr, end);
    return itr;
}

static const uint8_t* readQuotedString(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    if (itr == end || (*itr != '"' && *itr != '\''))
    {
        return reportError(p, "Expecting a '\"'.", end);
    }

    uint8_t quote = *itr++;

    while (itr != end && *itr != quote)
    {
        if (*itr == '\\')
        {
            if (++itr + 1 == end)
                return reportError(p, "Unclosed string", end);
        }
        ++itr;
    }

    return expect(p, quote, itr, end);
}

static const uint8_t* readNumber(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    while (itr != end &&
           (isAlnum(*itr) || *itr == '+' || *itr == '-' || *itr == '.'))
    {
        ++itr;
    }

    return itr;
}

static const uint8_t* read(
    OE_JsonParser* v,
    const uint8_t* itr,
    const uint8_t* end);

// Read array object.
// '['
//     elem ','
//     elem ','
//      ...
// ']'
static const uint8_t* readArray(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    itr = expect(p, '[', itr, end);

    if (!p->parseFailed && p->interface.beginArray)
        if (p->interface.beginArray(p->data) != OE_OK)
            return end;

    // read properties of the object.
    while (itr != end && *itr != ']')
    {
        itr = read(p, itr, end);

        // each property is separated by a comma
        if (itr != end && *itr == ',')
            ++itr;
    }

    itr = expect(p, ']', itr, end);

    if (!p->parseFailed && p->interface.endArray)
        if (p->interface.endArray(p->data) != OE_OK)
            return end;

    return itr;
}

static const uint8_t* readObject(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end);

// Read a property.
// Each property is expressed as:
// [white-space] "property-name"  [white-space]  :   [white-space]
// property-value [white-space]
///    (1)          (2)               (3)       (4)     (5)          (6) (7)
static const uint8_t* readProperty(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    const uint8_t* prop_name = NULL;
    // (1) =>
    itr = skipWS(itr, end);

    // (2) =>
    prop_name = itr + 1; // skip starting quote
    itr = readQuotedString(p, itr, end);

    if (!p->parseFailed && p->interface.propertyName)
        if (p->interface.propertyName(
                p->data, prop_name, itr - prop_name - 1) != OE_OK)
            return end;

    // (3) =>
    itr = skipWS(itr, end);

    // (4) =>
    itr = expect(p, ':', itr, end);

    // (5) =>
    itr = skipWS(itr, end);

    // (6) =>
    itr = read(p, itr, end);

    // (7) =>
    return skipWS(itr, end);
}

// Read a record object.
// '{'
//      property ','
//      property ','
//      ...
// '}'
static const uint8_t* readObject(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    itr = expect(p, '{', itr, end);

    if (!p->parseFailed && p->interface.beginObject)
        if (p->interface.beginObject(p->data) != OE_OK)
            return end;

    // read properties of the object.
    while (itr != end && *itr != '}')
    {
        itr = readProperty(p, itr, end);

        // each property is separated by a comma
        if (itr != end && *itr == ',')
            ++itr;
    }

    itr = expect(p, '}', itr, end);

    if (!p->parseFailed && p->interface.endObject)
        if (p->interface.endObject(p->data) != OE_OK)
            return end;

    return itr;
}

static const uint8_t* read(
    OE_JsonParser* p,
    const uint8_t* itr,
    const uint8_t* end)
{
    const uint8_t* start = NULL;

    // skip leading whitespace
    itr = skipWS(itr, end);
    start = itr;

    if (itr == end)
        return reportError(p, "Unexpected end of input.", end);

    if (isAlnum(*itr))
    {
        itr = readNumber(p, itr, end);
        if (!p->parseFailed && p->interface.number)
            if (p->interface.number(p->data, start, itr - start) != OE_OK)
                return end;
    }
    else if (*itr == '"' || *itr == '\'')
    {
        itr = readQuotedString(p, itr, end);
        if (!p->parseFailed && p->interface.string)
            if (p->interface.string(p->data, start, itr - start) != OE_OK)
                return end;
    }
    else if (*itr == '[')
    {
        itr = readArray(p, itr, end);
    }
    else // if (*itr == '{')
    {
        itr = readObject(p, itr, end);
    }

    return skipWS(itr, end);
}

OE_Result OE_ParseJson(
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

    itr = read(&p, itr, end);
    if (itr == end && !p.parseFailed)
        return OE_OK;
    return OE_FAILURE;
}

OE_EXTERNC_END
