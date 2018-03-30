// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/aesm.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/mem.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/*
**==============================================================================
**
** This module implements a socket client to AESM (SGX Application Enclave
** Services Manager). On linux, this service is called 'aesmd'. See if it
** is running with this command:
**
**     $ services aesmd status
**
** References:
**
**     See messages.proto from the Intel SGX SDK for the interface.
**
**==============================================================================
*/

#define AESM_SOCKET "/var/run/aesmd/aesm.socket"

typedef enum _WireType {
    WIRETYPE_VARINT = 0,
    WIRETYPE_LENGTH_DELIMITED = 2
} WireType;

#define AESM_MAGIC 0x4efaa2a3

typedef enum _MessageType {
    MESSAGE_TYPE_INIT_QUOTE = 1,
    MESSAGE_TYPE_GET_QUOTE = 2,
    MESSAGE_TYPE_GET_LAUNCH_TOKEN = 3
} MessageType;

struct _AESM
{
    uint32_t magic;
    int sock;
};

static int _AESMValid(const AESM* aesm)
{
    return aesm != NULL && aesm->magic == AESM_MAGIC;
}

static int _MakeTag(uint8_t fieldNum, WireType wireType, uint8_t* tag)
{
    int ret = -1;

    /* Initialize the tag in case of failure */
    if (tag)
        *tag = 0;

    /* Check parameter */
    if (!tag)
        goto done;

    /* Check for overflow (fieldNum will occupy the upper 5 bits) */
    if (fieldNum & 0xE0)
        goto done;

    /* Check for overflow (wireType will occupy the lower 3 bits) */
    if ((uint8_t)wireType & 0xF8)
        goto done;

    /* Form the tag */
    *tag = (fieldNum << 3) | (uint8_t)wireType;

    ret = 0;

done:
    return ret;
}

static int _PackVariantUint32(mem_t* buf, uint32_t x)
{
    uint8_t data[8];
    uint8_t* p = data;
    const uint8_t* end = data + sizeof(data);

    while (x >= 0x80)
    {
        if (p == end)
            return -1;

        *p++ = (uint8_t)(x | 0x80);
        x >>= 7;
    }

    if (p == end)
        return -1;

    *p++ = (uint8_t)(x);

    return mem_cat(buf, data, p - data);
}

static int _PackTag(mem_t* buf, uint8_t fieldNum, WireType wireType)
{
    uint8_t tag;

    if (_MakeTag(fieldNum, wireType, &tag) != 0)
        return -1;

    return mem_cat(buf, &tag, sizeof(uint8_t));
}

static ssize_t _UnpackTag(const mem_t* buf, size_t pos, uint8_t* tag)
{
    size_t size = sizeof(uint8_t);

    if (pos + size > mem_size(buf))
        return -1;

    memcpy(tag, mem_ptr_at(buf, pos), size);
    return pos + size;
}

static ssize_t _UnpackVariantUint32(mem_t* buf, size_t pos, uint32_t* value)
{
    const uint8_t* p;
    uint32_t result = 0;
    int count = 0;
    uint32_t b;

    if (value)
        *value = 0;

    p = (const uint8_t*)mem_ptr_at(buf, pos);

    do
    {
        /* Check for overflow */
        if (count == sizeof(uint32_t))
            return -1;

        /* If buffer is exhausted */
        if (p == mem_end(buf))
            return -1;

        b = *p;
        result |= (uint32_t)(b & 0x7F) << (7 * count);
        p++;
        count++;
    } while (b & 0x80);

    *value = result;

    return pos + count;
}

static OE_Result _PackBytes(
    mem_t* buf,
    uint8_t fieldNum,
    const void* data,
    uint32_t size)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t tag;

    if (_MakeTag(fieldNum, WIRETYPE_LENGTH_DELIMITED, &tag) != 0)
        OE_THROW(OE_FAILURE);

    if (mem_cat(buf, &tag, sizeof(tag)) != 0)
        OE_THROW(OE_FAILURE);

    if (_PackVariantUint32(buf, size) != 0)
        OE_THROW(OE_FAILURE);

    if (mem_cat(buf, data, size) != 0)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:
    return result;
}

static int _PackVarInt(mem_t* buf, uint8_t fieldNum, uint64_t value)
{
    OE_Result result = OE_UNEXPECTED;

    if (_PackTag(buf, fieldNum, WIRETYPE_VARINT) != 0)
        OE_THROW(OE_FAILURE);

    if (_PackVariantUint32(buf, value) != 0)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _UnpackVarInt(
    mem_t* buf,
    size_t* pos,
    uint8_t fieldNum,
    uint32_t* value)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t tag;
    uint8_t tmpTag;

    if ((*pos = _UnpackTag(buf, *pos, &tag)) == -1)
        OE_THROW(OE_FAILURE);

    if (_MakeTag(fieldNum, WIRETYPE_VARINT, &tmpTag) != 0)
        OE_THROW(OE_FAILURE);

    if (tag != tmpTag)
        OE_THROW(OE_FAILURE);

    if ((*pos = _UnpackVariantUint32(buf, *pos, value)) == -1)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _UnpackLengthDelimited(
    mem_t* buf,
    size_t* pos,
    uint8_t fieldNum,
    void* data,
    size_t dataSize)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t tag = 0;
    uint8_t tmpTag = 0;
    uint32_t size;

    if ((*pos = _UnpackTag(buf, *pos, &tag)) == -1)
        OE_THROW(OE_FAILURE);

    if (_MakeTag(fieldNum, WIRETYPE_LENGTH_DELIMITED, &tmpTag) != 0)
        OE_THROW(OE_FAILURE);

    if (tag != tmpTag)
        OE_THROW(OE_FAILURE);

    if ((*pos = _UnpackVariantUint32(buf, *pos, &size)) == -1)
        OE_THROW(OE_FAILURE);

    if (size > dataSize)
        OE_THROW(OE_FAILURE);

    memcpy(data, mem_ptr_at(buf, *pos), size);

    *pos += size;

    result = OE_OK;

OE_CATCH:
    return result;
}

static int _Read(int sock, void* data, size_t size)
{
    ssize_t n;

    if ((n = read(sock, data, size)) != size)
        return -1;

    return 0;
}

static int _Write(int sock, const void* data, size_t size)
{
    ssize_t n;

    if ((n = write(sock, data, size)) != size)
        return -1;

    return 0;
}

static OE_Result _WriteRequest(
    AESM* aesm,
    MessageType messageType,
    const mem_t* message)
{
    OE_Result result = OE_UNEXPECTED;
    mem_t envelope = MEM_DYNAMIC_INIT;

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    printf("=== _WriteRequest:\n");
    OE_HexDump(mem_ptr(message), mem_size(message));
#endif

    /* Wrap message in envelope */
    OE_TRY(
        _PackBytes(
            &envelope, messageType, mem_ptr(message), mem_size(message)));

    /* Send the envelope to the AESM service */
    {
        uint32_t size = (uint32_t)mem_size(&envelope);

        /* Send message size */
        if (_Write(aesm->sock, &size, sizeof(uint32_t)) != 0)
            OE_THROW(OE_FAILURE);

        /* Send message data */
        if (_Write(aesm->sock, mem_ptr(&envelope), mem_size(&envelope)) != 0)
            OE_THROW(OE_FAILURE);
    }

    result = OE_OK;

OE_CATCH:

    mem_free(&envelope);

    return result;
}

static OE_Result _ReadResponse(
    AESM* aesm,
    MessageType messageType,
    mem_t* message)
{
    OE_Result result = OE_UNEXPECTED;
    uint32_t size;
    mem_t envelope = MEM_DYNAMIC_INIT;

    mem_clear(message);

    /* Read the ENVELOPE from the AESM service */
    {
        /* Read the envelope size */
        if (_Read(aesm->sock, &size, sizeof(uint32_t)) != 0)
            OE_THROW(OE_FAILURE);

        /* Expand the buffer */
        if (mem_resize(&envelope, size) != 0)
            OE_THROW(OE_FAILURE);

        /* Read the message */
        if (_Read(aesm->sock, mem_mutable_ptr(&envelope), size) != 0)
            OE_THROW(OE_FAILURE);
    }

    /* Copy envelope contents into MESSAGE */
    {
        uint8_t tag;
        uint8_t tmpTag;
        size_t pos = 0;
        uint32_t size;

        /* Get the tag of this payload */
        if ((pos = _UnpackTag(&envelope, pos, &tag)) == (size_t)-1)
            OE_THROW(OE_FAILURE);

        if (_MakeTag(messageType, WIRETYPE_LENGTH_DELIMITED, &tmpTag) != 0)
            OE_THROW(OE_FAILURE);

        if (tag != tmpTag)
            OE_THROW(OE_FAILURE);

        /* Get the size of this payload */
        if ((pos = _UnpackVariantUint32(&envelope, pos, &size)) == (size_t)-1)
            OE_THROW(OE_FAILURE);

        /* Check the size (must equal unread bytes in envelope) */
        if (size != mem_size(&envelope) - pos)
            OE_THROW(OE_FAILURE);

        /* Read the message from the envelope */
        mem_cat(message, mem_ptr(&envelope) + pos, size);
    }

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    printf("=== _ReadResponse():\n");
    OE_HexDump(mem_ptr(message), mem_size(message));
#endif

    result = OE_OK;

OE_CATCH:

    mem_free(&envelope);

    return result;
}

AESM* AESMConnect()
{
    int sock = -1;
    struct sockaddr_un addr;
    AESM* aesm = NULL;

    /* Create a socket for connecting to the AESM service */
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        return NULL;

    /* Initialize the address */
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, AESM_SOCKET, sizeof(addr.sun_path));

    /* Connect to the AESM service */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sock);
        return NULL;
    }

    /* Allocate and initialize the AESM struct */
    {
        if (!(aesm = (AESM*)malloc(sizeof(AESM))))
        {
            close(sock);
            return NULL;
        }

        aesm->magic = AESM_MAGIC;
        aesm->sock = sock;
    }

    return aesm;
}

void AESMDisconnect(AESM* aesm)
{
    if (_AESMValid(aesm))
    {
        close(aesm->sock);
        memset(aesm, 0xDD, sizeof(AESM));
    }
}

OE_Result AESMGetLaunchToken(
    AESM* aesm,
    uint8_t mrenclave[OE_SHA256_SIZE],
    uint8_t modulus[OE_KEY_SIZE],
    const OE_SGXAttributes* attributes,
    SGX_LaunchToken* launchToken)
{
    OE_Result result = OE_UNEXPECTED;
    uint64_t timeout = 15000;
    mem_t request = MEM_DYNAMIC_INIT;
    mem_t response = MEM_DYNAMIC_INIT;

    if (launchToken)
        memset(launchToken, 0, sizeof(SGX_LaunchToken));

    /* Reject invalid parameters */
    if (!_AESMValid(aesm) || !mrenclave || !modulus || !attributes)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Build the PAYLOAD */
    {
        /* Pack MRENCLAVE */
        OE_TRY(_PackBytes(&request, 1, mrenclave, OE_SHA256_SIZE));

        /* Pack MODULUS */
        OE_TRY(_PackBytes(&request, 2, modulus, OE_KEY_SIZE));

        /* Pack ATTRIBUTES */
        OE_TRY(_PackBytes(&request, 3, attributes, sizeof(OE_SGXAttributes)));

        /* Pack TIMEOUT */
        OE_TRY(_PackVarInt(&request, 9, timeout));
    }

    /* Send the request to the AESM service */
    OE_TRY(_WriteRequest(aesm, MESSAGE_TYPE_GET_LAUNCH_TOKEN, &request));

    /* Receive the response from AESM service */
    OE_TRY(_ReadResponse(aesm, MESSAGE_TYPE_GET_LAUNCH_TOKEN, &response));

    /* Unpack the response */
    {
        size_t pos = 0;

        /* Unpack the error code */
        {
            uint32_t errcode;
            OE_TRY(_UnpackVarInt(&response, &pos, 1, &errcode));

            if (errcode != 0)
                OE_THROW(OE_FAILURE);
        }

        /* Unpack the launch token */
        OE_TRY(
            _UnpackLengthDelimited(
                &response, &pos, 2, launchToken, sizeof(SGX_LaunchToken)));
    }

    result = OE_OK;

OE_CATCH:

    mem_free(&request);
    mem_free(&response);

    return result;
}

OE_Result AESMInitQuote(
    AESM* aesm,
    SGX_TargetInfo* targetInfo,
    SGX_EPIDGroupID* epidGroupID)
{
    OE_Result result = OE_UNEXPECTED;
    uint64_t timeout = 15000;
    mem_t request = MEM_DYNAMIC_INIT;
    mem_t response = MEM_DYNAMIC_INIT;

    if (targetInfo)
        memset(targetInfo, 0, sizeof(SGX_TargetInfo));

    /* Reject invalid parameters */
    if (!_AESMValid(aesm) || !targetInfo || !epidGroupID)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Build the PAYLOAD */
    {
        /* Pack TIMEOUT */
        OE_TRY(_PackVarInt(&request, 9, timeout));
    }

    /* Send the request to the AESM service */
    OE_TRY(_WriteRequest(aesm, MESSAGE_TYPE_INIT_QUOTE, &request));

    /* Receive the response from AESM service */
    OE_TRY(_ReadResponse(aesm, MESSAGE_TYPE_INIT_QUOTE, &response));

    /* Unpack the response */
    {
        size_t pos = 0;

        /* Unpack the error code */
        {
            uint32_t errcode;
            OE_TRY(_UnpackVarInt(&response, &pos, 1, &errcode));

            if (errcode != 0)
                OE_THROW(OE_FAILURE);
        }

        /* Unpack targetInfo */
        OE_TRY(
            _UnpackLengthDelimited(
                &response, &pos, 2, targetInfo, sizeof(SGX_TargetInfo)));

        /* Unpack epidGroupID */
        OE_TRY(
            _UnpackLengthDelimited(
                &response, &pos, 3, epidGroupID, sizeof(SGX_EPIDGroupID)));
    }

    result = OE_OK;

OE_CATCH:

    mem_free(&request);
    mem_free(&response);

    return result;
}

OE_Result AESMGetQuote(
    AESM* aesm,
    const SGX_Report* report,
    SGX_QuoteType quoteType,
    const SGX_SPID* spid,
    const SGX_Nonce* nonce,
    const uint8_t* signatureRevocationList,
    uint32_t signatureRevocationListSize,
    SGX_Report* reportOut, /* ATTN: support this! */
    SGX_Quote* quote,
    size_t quoteSize)
{
    uint64_t timeout = 15000;
    mem_t request = MEM_DYNAMIC_INIT;
    mem_t response = MEM_DYNAMIC_INIT;
    OE_Result result = OE_UNEXPECTED;

    /* Zero initialize the quote */
    if (quote)
        memset(quote, 0, quoteSize);

    /* Check for invalid parameters */
    if (!_AESMValid(aesm) || !report || !spid || !quote || !quoteSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Build the PAYLOAD */
    {
        /* Pack REPORT */
        OE_TRY(_PackBytes(&request, 1, report, sizeof(SGX_Report)));

        /* Pack QUOTE-TYPE */
        OE_TRY(_PackVarInt(&request, 2, quoteType));

        /* Pack SPID */
        OE_TRY(_PackBytes(&request, 3, spid, sizeof(SGX_SPID)));

        /* Pack NONCE */
        if (nonce)
            OE_TRY(_PackBytes(&request, 4, nonce, sizeof(SGX_Nonce)));

        /* Pack SIGNATURE-REVOCATION-LIST */
        if (signatureRevocationListSize)
        {
            OE_TRY(
                _PackBytes(
                    &request,
                    5,
                    signatureRevocationList,
                    signatureRevocationListSize));
        }

        /* Pack QUOTE-SIZE */
        OE_TRY(_PackVarInt(&request, 6, quoteSize));

        /* Pack boolean indicating whether REPORT-OUT is present */
        if (reportOut)
            OE_TRY(_PackVarInt(&request, 7, 1));

        /* Pack TIMEOUT */
        OE_TRY(_PackVarInt(&request, 9, timeout));
    }

    /* Send the request to the AESM service */
    OE_TRY(_WriteRequest(aesm, MESSAGE_TYPE_GET_QUOTE, &request));

    /* Receive the response from AESM service */
    OE_TRY(_ReadResponse(aesm, MESSAGE_TYPE_GET_QUOTE, &response));

    /* Unpack the response */
    {
        size_t pos = 0;

        /* Unpack the error code */
        {
            uint32_t errcode;
            OE_TRY(_UnpackVarInt(&response, &pos, 1, &errcode));

            if (errcode != 0)
                OE_THROW(OE_FAILURE);
        }

        /* Unpack quote */
        OE_TRY(_UnpackLengthDelimited(&response, &pos, 2, quote, quoteSize));

        /* Unpack optional reportOut */
        if (reportOut)
        {
            OE_TRY(
                _UnpackLengthDelimited(
                    &response, &pos, 3, reportOut, sizeof(SGX_Report)));
        }
    }

    result = OE_OK;

OE_CATCH:

    return result;
}
