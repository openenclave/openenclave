// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/host.h>
#include <openenclave/internal/aesm.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
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

#define OE_ERROR_UNPACK ((size_t)-1)

#define AESM_SOCKET "/var/run/aesmd/aesm.socket"

typedef enum _wire_type
{
    WIRE_TYPE_VARINT = 0,
    WIRE_TYPE_LENGTH_DELIMITED = 2
} wire_type_t;

#define AESM_MAGIC 0x4efaa2a3

typedef enum _message_type
{
    MESSAGE_TYPE_INIT_QUOTE = 1,
    MESSAGE_TYPE_GET_QUOTE = 2,
    MESSAGE_TYPE_GET_LAUNCH_TOKEN = 3
} message_type_t;

struct _aesm
{
    uint32_t magic;
    int sock;
};

static int _aesm_valid(const aesm_t* aesm)
{
    return aesm != NULL && aesm->magic == AESM_MAGIC;
}

static int _make_tag(uint8_t field_num, wire_type_t wire_type, uint8_t* tag)
{
    int ret = -1;

    /* Initialize the tag in case of failure */
    if (tag)
        *tag = 0;

    /* Check parameter */
    if (!tag)
        goto done;

    /* Check for overflow (field_num will occupy the upper 5 bits) */
    if (field_num & 0xE0)
        goto done;

    /* Check for overflow (wire_type will occupy the lower 3 bits) */
    if ((uint8_t)wire_type & 0xF8)
        goto done;

    /* Form the tag */
    *tag = (uint8_t)((field_num << 3) | (uint8_t)wire_type);

    ret = 0;

done:
    return ret;
}

static int _pack_variant_uint32(mem_t* buf, uint32_t x)
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

    return mem_cat(buf, data, (size_t)(p - data));
}

static int _pack_tag(mem_t* buf, uint8_t field_num, wire_type_t wire_type)
{
    uint8_t tag;

    if (_make_tag(field_num, wire_type, &tag) != 0)
        return -1;

    return mem_cat(buf, &tag, sizeof(uint8_t));
}

static ssize_t _unpack_tag(const mem_t* buf, size_t pos, uint8_t* tag)
{
    size_t size = sizeof(uint8_t);

    if (pos + size > mem_size(buf))
        return -1;

    if (oe_memcpy_s(tag, sizeof(*tag), mem_ptr_at(buf, pos), size) != OE_OK)
        return -1;

    if (pos + size > OE_SSIZE_MAX)
        return -1;

    return (ssize_t)(pos + size);
}

static ssize_t _unpack_variant_uint32(mem_t* buf, size_t pos, uint32_t* value)
{
    const uint8_t* p;
    uint32_t result = 0;
    size_t count = 0;
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

    if (pos + count > OE_SSIZE_MAX)
        return -1;

    return (ssize_t)(pos + count);
}

static oe_result_t _pack_bytes(
    mem_t* buf,
    uint8_t field_num,
    const void* data,
    uint32_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;

    if (_make_tag(field_num, WIRE_TYPE_LENGTH_DELIMITED, &tag) != 0)
        OE_RAISE(OE_FAILURE);

    if (mem_cat(buf, &tag, sizeof(tag)) != 0)
        OE_RAISE(OE_FAILURE);

    if (_pack_variant_uint32(buf, size) != 0)
        OE_RAISE(OE_FAILURE);

    if (mem_cat(buf, data, size) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _pack_var_int(mem_t* buf, uint8_t field_num, uint64_t value)
{
    oe_result_t result = OE_UNEXPECTED;

    if (_pack_tag(buf, field_num, WIRE_TYPE_VARINT) != 0)
        OE_RAISE(OE_FAILURE);

    if (value > OE_UINT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_pack_variant_uint32(buf, (uint32_t)value) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _unpack_var_int(
    mem_t* buf,
    size_t* pos,
    uint8_t field_num,
    uint32_t* value)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag;
    uint8_t tmp_tag;

    if ((*pos = (size_t)_unpack_tag(buf, *pos, &tag)) == OE_ERROR_UNPACK)
        OE_RAISE(OE_FAILURE);

    if (_make_tag(field_num, WIRE_TYPE_VARINT, &tmp_tag) != 0)
        OE_RAISE(OE_FAILURE);

    if (tag != tmp_tag)
        OE_RAISE(OE_FAILURE);

    if ((*pos = (size_t)_unpack_variant_uint32(buf, *pos, value)) ==
        OE_ERROR_UNPACK)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _unpack_length_delimited(
    mem_t* buf,
    size_t* pos,
    uint8_t field_num,
    void* data,
    size_t data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag = 0;
    uint8_t tmp_tag = 0;
    uint32_t size;

    if ((*pos = (size_t)_unpack_tag(buf, *pos, &tag)) == OE_ERROR_UNPACK)
        OE_RAISE(OE_FAILURE);

    if (_make_tag(field_num, WIRE_TYPE_LENGTH_DELIMITED, &tmp_tag) != 0)
        OE_RAISE(OE_FAILURE);

    if (tag != tmp_tag)
        OE_RAISE(OE_FAILURE);

    if ((*pos = (size_t)_unpack_variant_uint32(buf, *pos, &size)) ==
        OE_ERROR_UNPACK)
        OE_RAISE(OE_FAILURE);

    if (size > data_size)
        OE_RAISE(OE_FAILURE);

    OE_CHECK(oe_memcpy_s(data, data_size, mem_ptr_at(buf, *pos), size));

    *pos += size;

    result = OE_OK;

done:
    return result;
}

static int _read(int sock, void* data, size_t size)
{
    ssize_t n;

    if ((n = read(sock, data, size)) != (ssize_t)size)
        return -1;

    return 0;
}

static int _write(int sock, const void* data, size_t size)
{
    ssize_t n;

    if ((n = write(sock, data, size)) != (ssize_t)size)
        return -1;

    return 0;
}

static oe_result_t _write_request(
    aesm_t* aesm,
    message_type_t message_type,
    const mem_t* message)
{
    oe_result_t result = OE_UNEXPECTED;
    mem_t envelope = MEM_DYNAMIC_INIT;

    OE_TRACE_INFO("=== _write_request:\n");
    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
    {
        oe_hex_dump(mem_ptr(message), mem_size(message));
    }

    /* Wrap message in envelope */
    OE_CHECK(_pack_bytes(
        &envelope,
        (uint8_t)message_type,
        mem_ptr(message),
        (uint32_t)mem_size(message)));

    /* Send the envelope to the AESM service */
    {
        uint32_t size = (uint32_t)mem_size(&envelope);

        /* Send message size */
        if (_write(aesm->sock, &size, sizeof(uint32_t)) != 0)
            OE_RAISE(OE_FAILURE);

        /* Send message data */
        if (_write(aesm->sock, mem_ptr(&envelope), mem_size(&envelope)) != 0)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:

    mem_free(&envelope);

    return result;
}

static oe_result_t _read_response(
    aesm_t* aesm,
    message_type_t message_type,
    mem_t* message)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t size;
    mem_t envelope = MEM_DYNAMIC_INIT;

    mem_clear(message);

    /* Read the ENVELOPE from the AESM service */
    {
        /* Read the envelope size */
        if (_read(aesm->sock, &size, sizeof(uint32_t)) != 0)
            OE_RAISE(OE_FAILURE);

        /* Expand the buffer */
        if (mem_resize(&envelope, size) != 0)
            OE_RAISE(OE_FAILURE);

        /* Read the message */
        if (_read(aesm->sock, mem_mutable_ptr(&envelope), size) != 0)
            OE_RAISE(OE_FAILURE);
    }

    /* Copy envelope contents into MESSAGE */
    {
        uint8_t tag;
        uint8_t tmp_tag;
        size_t pos = 0;
        uint32_t size;

        /* Get the tag of this payload */
        if ((pos = (size_t)_unpack_tag(&envelope, pos, &tag)) ==
            OE_ERROR_UNPACK)
            OE_RAISE(OE_FAILURE);

        if (_make_tag(
                (uint8_t)message_type, WIRE_TYPE_LENGTH_DELIMITED, &tmp_tag) !=
            0)
            OE_RAISE(OE_FAILURE);

        if (tag != tmp_tag)
            OE_RAISE(OE_FAILURE);

        /* Get the size of this payload */
        if ((pos = (size_t)_unpack_variant_uint32(&envelope, pos, &size)) ==
            OE_ERROR_UNPACK)
            OE_RAISE(OE_FAILURE);

        /* Check the size (must equal unread bytes in envelope) */
        if (size != mem_size(&envelope) - (size_t)pos)
            OE_RAISE(OE_FAILURE);

        uint8_t* temp = (uint8_t*)mem_ptr(&envelope) + pos;

        /* Read the message from the envelope */
        mem_cat(message, (const void*)temp, (size_t)size);
    }

    OE_TRACE_INFO("=== _read_response():\n");
    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
    {
        oe_hex_dump(mem_ptr(message), mem_size(message));
    }

    result = OE_OK;

done:

    mem_free(&envelope);

    return result;
}

aesm_t* aesm_connect()
{
    int sock = -1;
    struct sockaddr_un addr;
    aesm_t* aesm = NULL;

    /* Create a socket for connecting to the AESM service */
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        goto done;

    /* Initialize the address */
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    oe_strncpy_s(
        addr.sun_path, sizeof(addr.sun_path), AESM_SOCKET, strlen(AESM_SOCKET));

    /* Connect to the AESM service */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sock);
        goto done;
    }

    /* Allocate and initialize the AESM struct */
    {
        if (!(aesm = (aesm_t*)malloc(sizeof(aesm_t))))
        {
            close(sock);
            goto done;
        }

        aesm->magic = AESM_MAGIC;
        aesm->sock = sock;
    }

done:

    if (aesm == NULL)
        OE_TRACE_ERROR("aesm_connect failed");

    return aesm;
}

void aesm_disconnect(aesm_t* aesm)
{
    if (_aesm_valid(aesm))
    {
        close(aesm->sock);
        memset(aesm, 0xDD, sizeof(aesm_t));
        free(aesm);
    }
}

oe_result_t aesm_get_launch_token(
    aesm_t* aesm,
    uint8_t mrenclave[OE_SHA256_SIZE],
    uint8_t modulus[OE_KEY_SIZE],
    const sgx_attributes_t* attributes,
    sgx_launch_token_t* launch_token)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t timeout = 15000;
    mem_t request = MEM_DYNAMIC_INIT;
    mem_t response = MEM_DYNAMIC_INIT;

    if (launch_token)
        memset(launch_token, 0, sizeof(sgx_launch_token_t));

    /* Reject invalid parameters */
    if (!_aesm_valid(aesm) || !mrenclave || !modulus || !attributes)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Build the PAYLOAD */
    {
        /* Pack MRENCLAVE */
        OE_CHECK(_pack_bytes(&request, 1, mrenclave, OE_SHA256_SIZE));

        /* Pack MODULUS */
        OE_CHECK(_pack_bytes(&request, 2, modulus, OE_KEY_SIZE));

        /* Pack ATTRIBUTES */
        OE_CHECK(
            _pack_bytes(&request, 3, attributes, sizeof(sgx_attributes_t)));

        /* Pack TIMEOUT */
        OE_CHECK(_pack_var_int(&request, 9, timeout));
    }

    /* Send the request to the AESM service */
    OE_CHECK(_write_request(aesm, MESSAGE_TYPE_GET_LAUNCH_TOKEN, &request));

    /* Receive the response from AESM service */
    OE_CHECK(_read_response(aesm, MESSAGE_TYPE_GET_LAUNCH_TOKEN, &response));

    /* Unpack the response */
    {
        size_t pos = 0;

        /* Unpack the error code */
        {
            uint32_t errcode;
            OE_CHECK(_unpack_var_int(&response, &pos, 1, &errcode));

            if (errcode != 0)
                OE_RAISE_MSG(OE_FAILURE, "errcode=0x%x", errcode);
        }

        /* Unpack the launch token */
        OE_CHECK(_unpack_length_delimited(
            &response, &pos, 2, launch_token, sizeof(sgx_launch_token_t)));
    }

    result = OE_OK;

done:
    mem_free(&request);
    mem_free(&response);

    return result;
}

oe_result_t aesm_init_quote(
    aesm_t* aesm,
    sgx_target_info_t* target_info,
    sgx_epid_group_id_t* epid_group_id)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t timeout = 15000;
    mem_t request = MEM_DYNAMIC_INIT;
    mem_t response = MEM_DYNAMIC_INIT;

    if (target_info)
        memset(target_info, 0, sizeof(sgx_target_info_t));

    /* Reject invalid parameters */
    if (!_aesm_valid(aesm) || !target_info || !epid_group_id)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Build the PAYLOAD */
    {
        /* Pack TIMEOUT */
        OE_CHECK(_pack_var_int(&request, 9, timeout));
    }

    /* Send the request to the AESM service */
    OE_CHECK(_write_request(aesm, MESSAGE_TYPE_INIT_QUOTE, &request));

    /* Receive the response from AESM service */
    OE_CHECK(_read_response(aesm, MESSAGE_TYPE_INIT_QUOTE, &response));

    /* Unpack the response */
    {
        size_t pos = 0;

        /* Unpack the error code */
        {
            uint32_t errcode;
            OE_CHECK(_unpack_var_int(&response, &pos, 1, &errcode));

            if (errcode != 0)
                OE_RAISE_MSG(OE_FAILURE, "errcode=0x%x", errcode);
        }

        /* Unpack target_info */
        OE_CHECK(_unpack_length_delimited(
            &response, &pos, 2, target_info, sizeof(sgx_target_info_t)));

        /* Unpack epid_group_id */
        OE_CHECK(_unpack_length_delimited(
            &response, &pos, 3, epid_group_id, sizeof(sgx_epid_group_id_t)));
    }

    result = OE_OK;

done:
    mem_free(&request);
    mem_free(&response);

    return result;
}

oe_result_t aesm_get_quote(
    aesm_t* aesm,
    const sgx_report_t* report,
    sgx_quote_type_t quote_type,
    const sgx_spid_t* spid,
    const sgx_nonce_t* nonce,
    const uint8_t* signature_revocation_list,
    uint32_t signature_revocation_list_size,
    sgx_report_t* report_out, /* ATTN: support this! */
    sgx_quote_t* quote,
    size_t quote_size)
{
    uint64_t timeout = 15000;
    mem_t request = MEM_DYNAMIC_INIT;
    mem_t response = MEM_DYNAMIC_INIT;
    oe_result_t result = OE_UNEXPECTED;

    /* Zero initialize the quote */
    if (quote)
        memset(quote, 0, quote_size);

    /* Check for invalid parameters */
    if (!_aesm_valid(aesm) || !report || !spid || !quote || !quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Build the PAYLOAD */
    {
        /* Pack REPORT */
        OE_CHECK(_pack_bytes(&request, 1, report, sizeof(sgx_report_t)));

        /* Pack QUOTE-TYPE */
        OE_CHECK(_pack_var_int(&request, 2, quote_type));

        /* Pack SPID */
        OE_CHECK(_pack_bytes(&request, 3, spid, sizeof(sgx_spid_t)));

        /* Pack NONCE */
        if (nonce)
            OE_CHECK(_pack_bytes(&request, 4, nonce, sizeof(sgx_nonce_t)));

        /* Pack SIGNATURE-REVOCATION-LIST */
        if (signature_revocation_list_size)
        {
            OE_CHECK(_pack_bytes(
                &request,
                5,
                signature_revocation_list,
                signature_revocation_list_size));
        }

        /* Pack QUOTE-SIZE */
        OE_CHECK(_pack_var_int(&request, 6, quote_size));

        /* Pack boolean indicating whether REPORT-OUT is present */
        if (report_out)
            OE_CHECK(_pack_var_int(&request, 7, 1));

        /* Pack TIMEOUT */
        OE_CHECK(_pack_var_int(&request, 9, timeout));
    }

    /* Send the request to the AESM service */
    OE_CHECK(_write_request(aesm, MESSAGE_TYPE_GET_QUOTE, &request));

    /* Receive the response from AESM service */
    OE_CHECK(_read_response(aesm, MESSAGE_TYPE_GET_QUOTE, &response));

    /* Unpack the response */
    {
        size_t pos = 0;

        /* Unpack the error code */
        {
            uint32_t errcode;
            OE_CHECK(_unpack_var_int(&response, &pos, 1, &errcode));

            if (errcode != 0)
                OE_RAISE_MSG(OE_FAILURE, "errcode=0x%x", errcode);
        }

        /* Unpack quote */
        OE_CHECK(
            _unpack_length_delimited(&response, &pos, 2, quote, quote_size));

        /* Unpack optional report_out */
        if (report_out)
        {
            OE_CHECK(_unpack_length_delimited(
                &response, &pos, 3, report_out, sizeof(sgx_report_t)));
        }
    }

    result = OE_OK;

done:
    return result;
}
