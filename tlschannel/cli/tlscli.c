// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <mbedtls/certs.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>

#include "tlscli.h"

#define DEBUG_LEVEL 1

#define UNIQUE_ID_SIZE 32
#define SIGNER_ID_SIZE 32
#define PRODUCT_ID_SIZE 16

typedef struct _identity
{
    uint32_t id_version;
    uint32_t security_version;
    uint64_t attributes;
    uint8_t unique_id[UNIQUE_ID_SIZE];
    uint8_t signer_id[SIGNER_ID_SIZE];
    uint8_t product_id[PRODUCT_ID_SIZE];
} identity_t;

typedef enum _enclave_type
{
    ENCLAVE_TYPE_AUTO = 1,
    ENCLAVE_TYPE_SGX = 2,
    ENCLAVE_TYPE_OPTEE = 3,
    __ENCLAVE_TYPE_MAX = 0xffffffff,
} enclave_type_t;

typedef struct _report
{
    size_t size;
    enclave_type_t type;
    size_t report_data_size;
    size_t enclave_report_size;
    uint8_t* report_data;
    uint8_t* enclave_report;
    identity_t identity;
} report_t;

static bool _started;
static const char* _pers = "ssl_client";
static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;

static void _clear_err(tlscli_err_t* err)
{
    if (err)
        err->buf[0] = '\0';
}

__attribute__((format(printf, 2, 3))) static void _put_err(
    tlscli_err_t* err,
    const char* fmt,
    ...)
{
    if (err)
    {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err->buf, sizeof(err->buf), fmt, ap);
        va_end(ap);
    }
}

__attribute__((format(printf, 3, 4))) void _put_mbedtls_err(
    tlscli_err_t* err,
    int code,
    const char* fmt,
    ...)
{
    _clear_err(err);

    if (err && code)
    {
        char buf1[1024];
        mbedtls_strerror(code, buf1, sizeof(buf1));

        char buf2[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf2, sizeof(buf2), fmt, ap);
        va_end(ap);

        snprintf(err->buf, sizeof(err->buf), "%s: %s", buf1, buf2);
    }
}

int tlscli_startup(tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (_started)
    {
        _put_err(err, "already initialized");
        goto done;
    }

    mbedtls_entropy_init(&_entropy);
    mbedtls_ctr_drbg_init(&_ctr_drbg);

#if !defined(NDEBUG)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    if ((r = mbedtls_ctr_drbg_seed(
             &_ctr_drbg,
             mbedtls_entropy_func,
             &_entropy,
             (const unsigned char*)_pers,
             strlen(_pers))) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_entropy_func()");
        ret = r;
        goto done;
    }

    _started = true;
    ret = 0;

done:

    if (ret != 0)
    {
        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
    }

    return ret;
}

int tlscli_shutdown(tlscli_err_t* err)
{
    int ret = -1;

    _clear_err(err);

    if (!_started)
    {
        _put_err(err, "not started");
        goto done;
    }

    mbedtls_entropy_free(&_entropy);
    mbedtls_ctr_drbg_free(&_ctr_drbg);

done:

    return ret;
}

static int _get_report_from_cert_data(
    const uint8_t* cert_data,
    size_t cert_size,
    report_t* report);

static int _cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    int ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    tlscli_t* cli = (tlscli_t*)data;
    const uint8_t* cert_data;
    size_t cert_size;
    report_t report;
    const identity_t* identity;

    *flags = (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    cert_data = crt->raw.p;
    cert_size = crt->raw.len;

    if (cert_size <= 0)
        goto done;

    if (!cli)
        goto done;

    if (_get_report_from_cert_data(cert_data, cert_size, &report) != 0)
    {
        goto done;
    }

    identity = &report.identity;

    if (cli->verify_identity)
    {
        if (cli->verify_identity(
                cli->verify_identity_arg,
                identity->unique_id,
                sizeof(identity->unique_id),
                identity->signer_id,
                sizeof(identity->signer_id),
                identity->product_id,
                sizeof(identity->product_id),
                identity->security_version) != 0)
        {
            goto done;
        }
    }

    ret = 0;
    *flags = 0;

done:

    return ret;
}

/* The mbedtls debug tracing function */
static void _mbedtls_dbg(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* str)
{
    (void)level;
    (void)ctx;

    printf("_mbedtls_dbg.cli: %s:%u: %s", file, line, str);
}

static int _configure_cli(
    tlscli_t* cli,
    bool debug,
    const char* crt_path,
    const char* pk_path,
    tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if ((r = mbedtls_x509_crt_parse_file(&cli->crt, crt_path) != 0))
    {
        _put_mbedtls_err(err, r, "%s", crt_path);
        ret = r;
        goto done;
    }

    if ((r = mbedtls_pk_parse_keyfile(&cli->pk, pk_path, "")) != 0)
    {
        _put_mbedtls_err(err, r, "%s", pk_path);
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_config_defaults(
             &cli->conf,
             MBEDTLS_SSL_IS_CLIENT,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_config_defaults");
        ret = r;
        goto done;
    }

    mbedtls_ssl_conf_rng(&cli->conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

    if (debug)
        mbedtls_ssl_conf_dbg(&cli->conf, _mbedtls_dbg, stdout);

    mbedtls_ssl_conf_authmode(&cli->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&cli->conf, _cert_verify_callback, cli);

    if ((r = mbedtls_ssl_conf_own_cert(&cli->conf, &cli->crt, &cli->pk)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_conf_own_cert");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_setup(&cli->ssl, &cli->conf)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_setup");
        ret = r;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int tlscli_connect(
    bool debug,
    const char* host,
    const char* port,
    verify_identity_function_t verify_identity,
    void* verify_identity_arg,
    const char* crt_path,
    const char* pk_path,
    tlscli_t** cli_out,
    tlscli_err_t* err)
{
    int ret = -1;
    int r;
    tlscli_t* cli = NULL;

    _clear_err(err);

    if (cli_out)
        *cli_out = NULL;

    if (!_started)
    {
        _put_err(err, "not started: please call tlscli_startup()");
        goto done;
    }

    if (!cli_out)
    {
        _put_err(err, "invalid cli parameter");
        goto done;
    }

    if (!host)
    {
        _put_err(err, "invalid host parameter");
        goto done;
    }

    if (!port)
    {
        _put_err(err, "invalid port parameter");
        goto done;
    }

    /* Initialize the cli structure */
    {
        if (!(cli = calloc(1, sizeof(tlscli_t))))
        {
            _put_err(err, "calloc() failed: out of memory");
            goto done;
        }

        cli->verify_identity = verify_identity;
        cli->verify_identity_arg = verify_identity_arg;

        mbedtls_net_init(&cli->net);
        mbedtls_ssl_init(&cli->ssl);
        mbedtls_ssl_config_init(&cli->conf);
        mbedtls_x509_crt_init(&cli->crt);
        mbedtls_pk_init(&cli->pk);
    }

    if ((r = mbedtls_net_connect(
             &cli->net, host, port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_net_connect()");
        ret = r;
        goto done;
    }

    if ((r = _configure_cli(cli, debug, crt_path, pk_path, err)) != 0)
    {
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_set_hostname(&cli->ssl, host)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_set_hostname");
        ret = r;
        goto done;
    }

    mbedtls_ssl_set_bio(
        &cli->ssl, &cli->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((r = mbedtls_ssl_handshake(&cli->ssl)) != 0)
    {
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_handshake");
            ret = r;
            goto done;
        }
    }

    if (mbedtls_ssl_get_verify_result(&cli->ssl) != 0)
    {
        mbedtls_ssl_close_notify(&cli->ssl);
        _put_err(err, "handshake failed");
        goto done;
    }

    *cli_out = cli;
    cli = NULL;

    ret = 0;

done:

    if (cli)
    {
        mbedtls_ssl_free(&cli->ssl);
        mbedtls_net_free(&cli->net);
        mbedtls_ssl_config_free(&cli->conf);
        mbedtls_x509_crt_free(&cli->crt);
        mbedtls_pk_free(&cli->pk);
        free(cli);
    }

    return ret;
}

int tlscli_read(tlscli_t* cli, void* data, size_t size, tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!cli)
    {
        _put_err(err, "invalid cli parameter");
        goto done;
    }

    if (!data)
    {
        _put_err(err, "invalid data parameter");
        goto done;
    }

    if (!size)
    {
        _put_err(err, "invalid size parameter");
        goto done;
    }

    for (;;)
    {
        memset(data, 0, size);
        r = mbedtls_ssl_read(&cli->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r <= 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_read");
            ret = r;
            goto done;
        }

        /* Save number of bytes read */
        ret = r;
        break;
    }

done:

    return ret;
}

int tlscli_write(
    tlscli_t* cli,
    const void* data,
    size_t size,
    tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!cli)
    {
        _put_err(err, "invalid cli parameter");
        goto done;
    }

    if (!data)
    {
        _put_err(err, "invalid data parameter");
        goto done;
    }

    if (!size)
    {
        _put_err(err, "invalid size parameter");
        goto done;
    }

    for (;;)
    {
        r = mbedtls_ssl_write(&cli->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r <= 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_write");
            ret = r;
            goto done;
        }

        ret = r;
        break;
    }

done:

    return ret;
}

int tlscli_destroy(tlscli_t* cli, tlscli_err_t* err)
{
    int ret = -1;

    _clear_err(err);

    if (!cli)
    {
        _put_err(err, "invalid cli parameter");
        goto done;
    }

    mbedtls_ssl_close_notify(&cli->ssl);

    mbedtls_ssl_free(&cli->ssl);
    mbedtls_net_free(&cli->net);
    mbedtls_ssl_config_free(&cli->conf);
    mbedtls_x509_crt_free(&cli->crt);
    mbedtls_pk_free(&cli->pk);

done:
    return ret;
}

void tlscli_put_err(const tlscli_err_t* err)
{
    if (err)
        fprintf(stderr, "error: %s\n", err->buf);
}

/*
**==============================================================================
**
** _extract_report_extension()
**
**     This function extracts the report extension from a X509 certificate.
**
**==============================================================================
*/

#define OID_STRING_SIZE 128

typedef enum _find_extension_result
{
    OKAY,
    NOT_FOUND,
    BUFFER_TOO_SMALL,
} find_extension_result_t;

typedef struct _find_extension_args
{
    find_extension_result_t result;
    const char* oid;
    uint8_t* data;
    size_t* size;
} find_extension_args_t;

/* Returns true when done */
typedef bool (*parse_extensions_callback_t)(
    const char* oid,
    const uint8_t* data,
    size_t size,
    void* args);

static int _parse_extensions(
    const mbedtls_x509_crt* crt,
    parse_extensions_callback_t callback,
    void* args)
{
    int ret = -1;
    uint8_t* p = crt->v3_ext.p;
    uint8_t* end = p + crt->v3_ext.len;
    size_t len;
    int rc;
    size_t index = 0;

    if (!p)
    {
        ret = 0;
        goto done;
    }

    /* Parse tag that introduces the extensions */
    {
        int tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

        /* Get the tag and length of the entire packet */
        rc = mbedtls_asn1_get_tag(&p, end, &len, tag);
        if (rc != 0)
            goto done;
    }

    /* Parse each extension of the form: [OID | CRITICAL | OCTETS] */
    while (end - p > 1)
    {
        char oidstr[OID_STRING_SIZE];
        int is_critical = 0;
        const uint8_t* octets;
        size_t octets_size;

        /* Parse the OID */
        {
            mbedtls_x509_buf oid;

            /* Parse the OID tag */
            {
                int tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

                rc = mbedtls_asn1_get_tag(&p, end, &len, tag);
                if (rc != 0)
                    goto done;

                oid.tag = p[0];
            }

            /* Parse the OID length */
            {
                rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID);
                if (rc != 0)
                    goto done;

                oid.len = len;
                oid.p = p;
                p += oid.len;
            }

            /* Convert OID to a string */
            rc = mbedtls_oid_get_numeric_string(oidstr, sizeof(oidstr), &oid);
            if (rc < 0)
                goto done;
        }

        /* Parse the critical flag */
        {
            rc = (mbedtls_asn1_get_bool(&p, end, &is_critical));
            if (rc != 0 && rc != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            {
                goto done;
            }
        }

        /* Parse the octet string */
        {
            const int tag = MBEDTLS_ASN1_OCTET_STRING;
            rc = mbedtls_asn1_get_tag(&p, end, &len, tag);
            if (rc != 0)
            {
                goto done;
            }

            octets = p;
            octets_size = len;
            p += len;
        }

        /* Invoke the caller's callback (returns true when done) */
        if (callback(oidstr, octets, octets_size, args) == true)
        {
            ret = 0;
            goto done;
        }

        /* Increment the index */
        index++;
    }

    ret = 0;

done:
    return ret;
}

static bool _find_extension_callback(
    const char* oid,
    const uint8_t* data,
    size_t size,
    void* args_)
{
    find_extension_args_t* args = (find_extension_args_t*)args_;

    if (strcmp(oid, args->oid) == 0)
    {
        /* If buffer is too small */
        if (size > *args->size)
        {
            *args->size = size;
            args->result = BUFFER_TOO_SMALL;
            return true;
        }

        if (args->data)
            memcpy(args->data, data, size);

        *args->size = size;
        args->result = OKAY;
        return true;
    }

    /* Keep parsing */
    return false;
}

static find_extension_result_t _find_extension(
    const mbedtls_x509_crt* cert,
    const char* oid,
    uint8_t* data,
    size_t* size)
{
    find_extension_result_t result = NOT_FOUND;

    /* Find the extension with the given OID using a callback */
    {
        find_extension_args_t args;
        args.result = NOT_FOUND;
        args.oid = oid;
        args.data = data;
        args.size = size;

        if (_parse_extensions(cert, _find_extension_callback, &args) != 0)
        {
            goto done;
        }

        result = args.result;
        goto done;
    }

done:

    return result;
}

static int _extract_report_extension(
    const uint8_t* cert_data,
    size_t cert_size,
    uint8_t** report_data_out,
    size_t* report_size_out)
{
    int ret = -1;
    mbedtls_x509_crt cert;
    uint8_t* report_data = NULL;
    size_t report_size = 0;
    static const char OID[] = "1.2.840.113556.10.1.1";

    mbedtls_x509_crt_init(&cert);

    if (report_data_out)
        *report_data_out = NULL;

    if (report_size_out)
        *report_size_out = 0;

    if (!cert_data || !cert_size)
        goto done;

    /* Initialize the certificate form the DER-encoded buffer */
    if (mbedtls_x509_crt_parse_der(&cert, cert_data, cert_size) != 0)
        goto done;

    /* Determine the size of the report extension */
    if (_find_extension(&cert, OID, NULL, &report_size) != BUFFER_TOO_SMALL)
        goto done;

    /* Allocate the report buffer */
    if (!(report_data = (uint8_t*)malloc(report_size)))
        goto done;

    /* Get the extension */
    if (_find_extension(&cert, OID, report_data, &report_size) != OKAY)
        goto done;

    if (report_data_out)
        *report_data_out = report_data;

    if (report_size_out)
        *report_size_out = report_size;

    report_data = NULL;

    ret = 0;

done:

    mbedtls_x509_crt_free(&cert);

    if (report_data)
        free(report_data);

    return ret;
}

typedef struct _sgx_attributes
{
    uint64_t flags;
    uint64_t xfrm;
} sgx_attributes_t;

#define SGX_CPUSVN_SIZE 16

#define SHA256_SIZE 32

typedef struct _sgx_report_data
{
    unsigned char field[64];
} sgx_report_data_t;

typedef struct _sgx_report_body
{
    /* (0) CPU security version */
    uint8_t cpusvn[SGX_CPUSVN_SIZE];

    /* (16) Selector for which fields are defined in SSA.MISC */
    uint32_t miscselect;

    /* (20) Reserved */
    uint8_t reserved1[28];

    /* (48) Enclave attributes */
    sgx_attributes_t attributes;

    /* (64) Enclave measurement */
    uint8_t mrenclave[SHA256_SIZE];

    /* (96) */
    uint8_t reserved2[32];

    /* (128) The value of the enclave's SIGNER measurement */
    uint8_t mrsigner[SHA256_SIZE];

    /* (160) */
    uint8_t reserved3[96];

    /* (256) Enclave product ID */
    uint16_t isvprodid;

    /* (258) Enclave security version */
    uint16_t isvsvn;

    /* (260) Reserved */
    uint8_t reserved4[60];

    /* (320) User report data */
    sgx_report_data_t report_data;
} sgx_report_body_t;

#define SGX_KEYID_SIZE 32
#define SGX_MAC_SIZE 16

typedef struct _sgx_report
{
    /* (0) */
    sgx_report_body_t body;

    /* (384) Id of key (?) */
    uint8_t keyid[SGX_KEYID_SIZE];

    /* (416) Message authentication code over fields of this structure */
    uint8_t mac[SGX_MAC_SIZE];
} sgx_report_t;

#define PACK_BEGIN _Pragma("pack(push, 1)")
#define PACK_END _Pragma("pack(pop)")

PACK_BEGIN
typedef struct _sgx_quote
{
    /* (0) */
    uint16_t version;

    /* (2) */
    uint16_t sign_type;

    /* (4) */
    uint8_t reserved[4];

    /* (8) */
    uint16_t qe_svn;

    /* (10) */
    uint16_t pce_svn;

    /* (12) */
    uint8_t uuid[16];

    /* (28) */
    uint8_t user_data[20];

    /* (48) */
    sgx_report_body_t report_body;

    /* (432) */
    uint32_t signature_len;

    /* (436) signature array (varying length) */
    uint8_t signature[];
} sgx_quote_t;
PACK_END

typedef enum _report_type
{
    REPORT_TYPE_SGX_LOCAL = 1,
    REPORT_TYPE_SGX_REMOTE = 2,
    __REPORT_TYPE_MAX = 0xffffffff,
} report_type_t;

typedef struct _report_header
{
    uint32_t version;
    report_type_t report_type;
    uint64_t report_size;
    uint8_t report[];
} report_header_t;

#define REPORT_HEADER_VERSION 1

static void _secure_zero_fill(volatile void* ptr, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--)
    {
        *p++ = 0;
    }
}

#define REPORT_ATTRIBUTES_DEBUG 0x0000000000000001ULL
#define REPORT_ATTRIBUTES_REMOTE 0x0000000000000002ULL

#define SGX_FLAGS_DEBUG 0x0000000000000002ULL

static int _parse_sgx_report_body(
    const sgx_report_body_t* body,
    bool remote,
    report_t* report)
{
    int ret = -1;

    _secure_zero_fill(report, sizeof(report_t));

    report->size = sizeof(report_t);
    report->type = ENCLAVE_TYPE_SGX;

    /*
     * Parse identity.
     */
    report->identity.id_version = 0x0;
    report->identity.security_version = body->isvsvn;

    if (body->attributes.flags & SGX_FLAGS_DEBUG)
        report->identity.attributes |= REPORT_ATTRIBUTES_DEBUG;

    if (remote)
        report->identity.attributes |= REPORT_ATTRIBUTES_REMOTE;

    if (sizeof(report->identity.unique_id) < sizeof(body->mrenclave))
        goto done;

    memcpy(
        report->identity.unique_id, body->mrenclave, sizeof(body->mrenclave));

    if (sizeof(report->identity.signer_id) < sizeof(body->mrsigner))
        goto done;

    memcpy(report->identity.signer_id, body->mrsigner, sizeof(body->mrsigner));

    report->identity.product_id[0] = (uint8_t)body->isvprodid & 0xFF;
    report->identity.product_id[1] = (uint8_t)((body->isvprodid >> 8) & 0xFF);

    report->report_data = (uint8_t*)&body->report_data;
    report->report_data_size = sizeof(sgx_report_data_t);
    report->enclave_report = (uint8_t*)body;
    report->enclave_report_size = sizeof(sgx_report_body_t);

    ret = 0;

done:
    return ret;
}

int _parse_report(
    const uint8_t* report_data,
    size_t report_size,
    report_t* report)
{
    const sgx_report_t* sgx_report = NULL;
    const sgx_quote_t* sgx_quote = NULL;
    report_header_t* header = (report_header_t*)report_data;
    int ret = -1;

    if (report_data == NULL || report == NULL)
        goto done;

    printf("%zu %zu\n", report_size, sizeof(report_header_t));
    if (report_size < sizeof(report_header_t))
        goto done;

    if (header->version != REPORT_HEADER_VERSION)
        goto done;

    if (header->report_size + sizeof(report_header_t) != report_size)
        goto done;

    if (header->report_type == REPORT_TYPE_SGX_LOCAL)
    {
        sgx_report = (const sgx_report_t*)header->report;

        if (_parse_sgx_report_body(&sgx_report->body, false, report) != 0)
            goto done;

        ret = 0;
    }
    else if (header->report_type == REPORT_TYPE_SGX_REMOTE)
    {
        sgx_quote = (const sgx_quote_t*)header->report;

        if (_parse_sgx_report_body(&sgx_quote->report_body, true, report) != 0)
            goto done;

        ret = 0;
    }
    else
    {
        goto done;
    }

done:

    return ret;
}

static int _get_report_from_cert_data(
    const uint8_t* cert_data,
    size_t cert_size,
    report_t* report)
{
    int ret = -1;
    uint8_t* report_data = NULL;
    size_t report_size;

    if (!cert_data || !cert_size || !report)
        goto done;

    if (_extract_report_extension(
            cert_data, cert_size, &report_data, &report_size) != 0)
    {
        goto done;
    }

    if (_parse_report(report_data, report_size, report) != 0)
        goto done;

    ret = 0;

done:

    if (report_data)
        free(report_data);

    return ret;
}
