// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <ctype.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/tests.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <map>
#include <string>
#include <vector>
#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#include "oeutil_u.h"

#if defined(__linux__)
#include <dlfcn.h>
#else
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
#include <openssl/applink.c>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#endif

#include "../../../common/attest_plugin.h"
#include "../../../common/sgx/collateral.h"
#include "../../../common/sgx/endorsements.h"
#include "../../../common/sgx/quote.h"
#include "../../../host/sgx/sgxquoteprovider.h"
#include "generate_evidence.h"
#include "parse_args_helper.h"
extern FILE* log_file;

#define DEFAULT_LOG_FILE "oeutil_generate_evidence.log"
#define ENCLAVE_FILENAME_SUFFIX "_enc.signed"
#define INPUT_PARAM_OPTION_FORMAT "--format"
#define INPUT_PARAM_OPTION_CERT "cert"
#define INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME "--endorsements"
#define INPUT_PARAM_OPTION_QUOTE_PROC "--quote-proc"
#define INPUT_PARAM_QUOTE_IN_PROC "in"
#define INPUT_PARAM_QUOTE_OUT_OF_PROC "out"
#define INPUT_PARAM_OPTION_VERIFY "--verify"
#define INPUT_PARAM_OPTION_OUT_FILE "--out"
#define INPUT_PARAM_OPTION_LOG_FILE "--log"
#define INPUT_PARAM_OPTION_VERBOSE "--verbose"
#define INPUT_PARAM_OPTION_BASELINE "--baseline"
#define INPUT_PARAM_OPTION_HELP "--help"
#define INPUT_PARAM_OPTION_LEGACY_REPORT_REMOTE "LEGACY_REPORT_REMOTE"
#define INPUT_PARAM_OPTION_SGX_ECDSA "SGX_ECDSA"
#define INPUT_PARAM_OPTION_SGX_EPID_LINKABLE "SGX_EPID_LINKABLE"
#define INPUT_PARAM_OPTION_SGX_EPID_UNLINKABLE "SGX_EPID_UNLINKABLE"
#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
#define INPUT_PARAM_OPTION_ROOT_PUB_KEY "--rootkey"
#endif
#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
#define INPUT_PARAM_OPTION_BYPASS_DATE "--bypass-date-check"
#endif
#define SHORT_INPUT_PARAM_OPTION_FORMAT "-f"
#define SHORT_INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME "-e"
#define SHORT_INPUT_PARAM_OPTION_QUOTE_PROC "-p"
#define SHORT_INPUT_PARAM_OPTION_VERIFY "-v"
#define SHORT_INPUT_PARAM_OPTION_OUT_FILE "-o"
#define SHORT_INPUT_PARAM_OPTION_LOG_FILE "-l"
#define SHORT_INPUT_PARAM_OPTION_BASELINE "-b"
#define SHORT_INPUT_PARAM_OPTION_HELP "-h"
#define SGX_AESM_ADDR "SGX_AESM_ADDR"
#if defined(_WIN32)
#define SGX_AESM_ADDR_MAXSIZE 32
#endif

#define SGX_EXTENSION_OID_STR "1.2.840.113741.1.13.1"
#define MAX_BUFFER_SIZE 65536

// Static constants for evidence UUIDs
static const oe_uuid_t _sgx_ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _sgx_epid_linkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_LINKABLE};
static const oe_uuid_t _sgx_epid_unlinkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_UNLINKABLE};

#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
// Override the root key used in
// common/sgx/tcbinfo.c:_trusted_root_key_pem
OE_EXTERNC const char* _trusted_root_key_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\n"
    "SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n"
    "-----END PUBLIC KEY-----\n";
#endif

#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
// common/sgx/quote.c
OE_EXTERNC bool _should_skip_date_check = false;
#endif

// Structure to store input parameters
typedef struct _input_parameters
{
    const char* private_key_filename;
    const char* public_key_filename;
    const char* out_filename;
    const char* log_filename;
#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
    const char* override_pubkey_filename;
#endif
    const char* endorsements_filename;
    const char* quote_proc;
    const char* baseline;
    bool generate_certificate;
    bool generate_legacy_report_remote;
    bool generate_sgx_ecdsa;
    bool generate_sgx_epid_linkable;
    bool generate_sgx_epid_unlinkable;
    bool verify;
    bool verbose;
} input_parameters_t;

static input_parameters_t _parameters;

void log(const char* fmt, ...)
{
    std::vector<char> buffer(4096);
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer.data(), buffer.size(), fmt, args);
    va_end(args);

    // ensure buf is always null-terminated
    buffer[buffer.size() - 1] = 0;

    if (log_file)
    {
        fprintf(log_file, "%s", buffer.data());
    }
    else
    {
        printf("%s", buffer.data());
    }
}

OE_INLINE uint16_t read_uint16(const uint8_t* p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

OE_INLINE uint32_t read_uint32(const uint8_t* p)
{
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static oe_result_t _read_key(const char* filename, uint8_t** data, size_t* size)
{
    FILE* fp;
    fopen_s(&fp, filename, "rb");
    size_t file_size;
    oe_result_t result = OE_FAILURE;
    uint8_t* memory = nullptr;

    if (fp == nullptr)
        goto done;

    // Find file size
    fseek(fp, 0, SEEK_END);
    file_size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Account for '\0'
    memory = (uint8_t*)malloc(file_size + 1);
    if (memory == nullptr)
    {
        printf("Failed to allocate memory.\n");
        goto done;
    }

    if (fread(memory, 1, file_size, fp) == file_size)
    {
        memory[file_size] = '\0';
        printf("Read in key: %s\n", memory);
    }
    else
    {
        printf("Failed to read in key: %s\n", filename);
        goto done;
    }

    *data = memory;
    *size = file_size + 1;
    memory = nullptr;

    result = OE_OK;

done:
    if (fp)
        fclose(fp);
    free(memory);

    return result;
}

static void decode_crl_der(const uint8_t* data, size_t data_size)
{
    X509_CRL* x509;
    BIO* input = BIO_new_mem_buf(data, (int)data_size);
    x509 = d2i_X509_CRL_bio(input, NULL);
    if (x509)
        X509_CRL_print_fp(log_file, x509);
    BIO_free_all(input);
}

static void decode_crl_pem(const uint8_t* data, size_t data_size)
{
    X509_CRL* x509;
    BIO* input = BIO_new_mem_buf(data, (int)data_size);
    x509 = PEM_read_bio_X509_CRL(input, NULL, NULL, NULL);
    if (x509)
        X509_CRL_print_fp(log_file, x509);
    BIO_free_all(input);
}

// DCAP client (libdcap_quoteprov) log callback to this function.
static void oeutil_quote_provider_log(
    sgx_ql_log_level_t level,
    const char* message)
{
    if (level < SGX_QL_LOG_ERROR || level > SGX_QL_LOG_NONE)
        level = SGX_QL_LOG_INFO;
    const char* level_string[] = {"ERROR", "INFO", "NONE"};

    log("dcap_quoteprov [%s]: %s\n", level_string[level], message);
}

// Set DCAP client (libdcap_quoteprov) log callback
static void set_log_callback()
{
    // Initialize quote provider and set log callback
    oe_initialize_quote_provider();
    oe_sgx_set_quote_provider_logger(oeutil_quote_provider_log);
}

oe_result_t output_file(
    const char* file_name,
    const uint8_t* data,
    size_t data_size)
{
    FILE* output = nullptr;
    fopen_s(&output, file_name, "wb");
    if (!output)
    {
        log("Failed to open output file %s\n", file_name);
        return OE_FAILURE;
    }
    fwrite(data, data_size, 1, output);
    fclose(output);
    return OE_OK;
}

static void _display_help(const char* command)
{
    printf(
        "Generate-evidence Usage: %s generate-evidence "
        "<options>\n",
        command);
    printf("options:\n");
    printf(
        "\t%s, %s <format_option>: generate evidence, a report, or a "
        "certificate, where format_option can be one of the following (case "
        "insensitive):\n",
        SHORT_INPUT_PARAM_OPTION_FORMAT,
        INPUT_PARAM_OPTION_FORMAT);
    printf(
        "\t\t%s <private_key> <public_key>: a remote attestation certificate "
        "in DER format.\n",
        INPUT_PARAM_OPTION_CERT);
    printf(
        "\t\t%s: a report in OE_FORMAT_UUID_LEGACY_REPORT_REMOTE format.\n",
        INPUT_PARAM_OPTION_LEGACY_REPORT_REMOTE);
    printf(
        "\t\t%s: evidence in OE_FORMAT_UUID_SGX_ECDSA format.\n",
        INPUT_PARAM_OPTION_SGX_ECDSA);
    printf(
        "\t%s, %s <in|out>: use SGX in-process or out-of-process quoting.\n",
        SHORT_INPUT_PARAM_OPTION_QUOTE_PROC,
        INPUT_PARAM_OPTION_QUOTE_PROC);
    printf(
        "\t%s, %s <filename>: generate an output file for a remote attestation "
        "certificate, a report, or evidence.\n",
        SHORT_INPUT_PARAM_OPTION_OUT_FILE,
        INPUT_PARAM_OPTION_OUT_FILE);
    printf(
        "\t%s, %s <filename>: output a report in LEGACY_REPORT_REMOTE format "
        "or evidence, and also its "
        "endorsements binary.\n",
        SHORT_INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME,
        INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME);
    printf(
        "\t%s, %s: verify the generated remote attestation certificate, "
        "report, or evidence.\n",
        SHORT_INPUT_PARAM_OPTION_VERIFY,
        INPUT_PARAM_OPTION_VERIFY);
    printf(
        "\t%s, %s <filename>: generate a log file (default: %s).\n",
        SHORT_INPUT_PARAM_OPTION_LOG_FILE,
        INPUT_PARAM_OPTION_LOG_FILE,
        DEFAULT_LOG_FILE);
    printf(
        "\t%s, %s <baseline>: baseline for evidence verification. Only valid "
        "when --verify/-v option is specified.\n",
        SHORT_INPUT_PARAM_OPTION_BASELINE,
        INPUT_PARAM_OPTION_BASELINE);
    printf("\t%s: enable verbose output.\n", INPUT_PARAM_OPTION_VERBOSE);
#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
    printf(
        "\t%s <pub key>: replace hard-coded Intel trusted public key with "
        "given one\n",
        INPUT_PARAM_OPTION_ROOT_PUB_KEY);
#endif
#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
    printf(
        "\t%s: bypass/ignore quote's date validity check\n",
        INPUT_PARAM_OPTION_BYPASS_DATE);
#endif
    printf("Examples:\n");
    printf("\t1. Show the verification results of evidence in SGX_ECDSA "
           "format:\n");
    printf("\t   oeutil generate-evidence -f sgx_ecdsa -v\n");
    printf("\t2. Generate and output a certificate:\n");
    printf("\t   oeutil generate -f cert private.pem public.pem -o cert.der\n");
    printf("\t3. Generate and output a report:\n");
    printf("\t   oeutil gen --format legacy_report_remote --out report.bin\n");
}

void dump_certificate(const uint8_t* data, size_t data_len)
{
    X509* x509;
    BIO* input = BIO_new_mem_buf(data, (int)data_len);
    x509 = d2i_X509_bio(input, nullptr);
    if (x509)
        X509_print_ex_fp(
            stdout,
            x509,
            XN_FLAG_COMPAT,
            XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DUMP_UNKNOWN_FIELDS);
    BIO_free_all(input);
}

void decode_certificate_pem(FILE* file, const uint8_t* data, size_t data_len)
{
    X509* x509;
    BIO* input = BIO_new_mem_buf(data, (int)data_len);
    x509 = PEM_read_bio_X509(input, NULL, 0, NULL);
    if (x509)
        X509_print_ex_fp(
            file,
            x509,
            XN_FLAG_COMPAT,
            XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DUMP_UNKNOWN_FIELDS);
    BIO_free_all(input);
}

void parse_certificate_extension(const uint8_t* data, size_t data_len)
{
    oe_result_t result = OE_FAILURE;
    oe_cert_chain_t cert_chain = {0};
    oe_cert_t leaf_cert = {0};
    oe_parsed_extension_info_t extension_info = {{0}};

    // get leaf cert to parse sgx extension
    oe_cert_chain_read_pem(&cert_chain, data, data_len);
    oe_cert_chain_get_leaf_cert(&cert_chain, &leaf_cert);

    result = oe_parse_sgx_extensions(&leaf_cert, &extension_info);
    if (result != OE_OK)
        goto done;

    printf(
        "\n    parsed qe certificate extension (%s) {\n",
        SGX_EXTENSION_OID_STR);
    printf("        ppid (hex): ");
    oe_hex_dump(extension_info.ppid, OE_COUNTOF(extension_info.ppid));
    printf("        comp_svn (hex): ");
    oe_hex_dump(extension_info.comp_svn, OE_COUNTOF(extension_info.comp_svn));
    printf("        pce_svn: 0x%x\n", extension_info.pce_svn);
    printf("        cpu_svn (hex): ");
    oe_hex_dump(extension_info.cpu_svn, OE_COUNTOF(extension_info.cpu_svn));
    printf("        pce_id (hex): ");
    oe_hex_dump(extension_info.pce_id, OE_COUNTOF(extension_info.pce_id));
    printf("        fmspc (hex): ");
    oe_hex_dump(extension_info.fmspc, OE_COUNTOF(extension_info.fmspc));
    printf("        sgx_type: %d\n", extension_info.sgx_type);
    printf("        opt_platform_instance_id (hex): ");
    oe_hex_dump(
        extension_info.opt_platform_instance_id,
        OE_COUNTOF(extension_info.opt_platform_instance_id));
    printf(
        "        opt_dynamic_platform: %s\n",
        extension_info.opt_dynamic_platform ? "true" : "false");
    printf(
        "        opt_cached_keys: %s\n",
        extension_info.opt_cached_keys ? "true" : "false");
    printf(
        "        opt_smt_enabled: %s\n",
        extension_info.opt_smt_enabled ? "true" : "false");
    printf("    } qe cert extension \n");
done:
    oe_cert_chain_free(&cert_chain);
    oe_cert_free(&leaf_cert);
}

void dump_certificate_chain(
    const uint8_t* data,
    size_t data_len,
    bool is_report_buffer)
{
    const char* pem = (char*)data;
    // This test tools output certificate chain in two scenarios:
    // 1. Log certificate chain in endorsement buffer to log file
    // 2. Print certificate chain in report buffer in verbose mode to stdout
    // Only the leaf certificate in report buffer contains sgx extension
    bool leaf_cert_extension = is_report_buffer;
    FILE* file = is_report_buffer ? stdout : log_file;

    // print decoded PEM certificate chain
    while (*pem)
    {
        const char* end;
        // The PEM certificate starts with "-----BEGIN CERTIFICATE-----"
        if (strncmp(
                pem, OE_PEM_BEGIN_CERTIFICATE, OE_PEM_BEGIN_CERTIFICATE_LEN) !=
            0)
            break;
        // Find the end of certificate ending with "-----END CERTIFICATE-----"
        if (!(end = strstr(pem, OE_PEM_END_CERTIFICATE)))
            break;
        end += OE_PEM_END_CERTIFICATE_LEN;
        // Print each certificate
        decode_certificate_pem(file, (uint8_t*)pem, (size_t)(end - pem));
        // Parse sgx extention in leaf certificate
        if (leaf_cert_extension)
        {
            parse_certificate_extension(data, data_len);
            leaf_cert_extension = false;
        }
        if (is_report_buffer)
            printf("\n");
        else
            log("\n");
        while (isspace(*end))
            end++;
        pem = end;
    }
}

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
static const oe_claim_t* find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return &(claims[i]);
    }
    return nullptr;
}

void print_claims(
    size_t claim_number,
    const char* claim_name,
    const uint8_t* claim_value,
    size_t claim_value_size,
    const char format_type)
{
    switch (format_type)
    {
        case 'u':
        {
            printf(
                "claims[%zu]: %s\n%u\n\n",
                claim_number,
                claim_name,
                *claim_value);
            break;
        }
        case 'x':
        {
            printf(
                "claims[%zu]: %s (%zu)\n0x",
                claim_number,
                claim_name,
                claim_value_size);
            for (size_t j = 0; j < claim_value_size; j++)
                printf("%02x", claim_value[j]);
            printf("\n\n");
            break;
        }
        case 's':
        {
            printf(
                "claims[%zu]: %s\n%s\n\n",
                claim_number,
                claim_name,
                claim_value);
            break;
        }
        case 'D':
        {
            printf("claims[%zu]: %s\n", claim_number, claim_name);
            uint32_t* date = (uint32_t*)claim_value;
            for (size_t j = 0; j < 6; j++)
                printf("%d ", date[j]);
            printf("\n\n");
            break;
        }
        default:
        {
            printf("The claim format is not recognised.\n");
        }
    }
}

void dump_claims(const oe_claim_t* claims, size_t claims_length)
{
    printf("\n%zu OE claims retrieved:\n\n", claims_length);

    /*
     * This map holds a mapping to claims and their expected
     * print format strings and needs to be updated when a
     * new claim is added. The convention followed is:
     * %u   : 'u'
     * %02x : 'x'
     * %s   : 's'
     * date : 'D'
     */
    std::map<std::string, char> claims_format{
        {"attributes", 'u'},
        {"format_uuid", 'x'},
        {"hardware_model", 'x'},
        {"id_version", 'u'},
        {"product_id", 'x'},
        {"security_version", 'u'},
        {"sgx_config_id", 'x'},
        {"sgx_config_svn", 'x'},
        {"sgx_crl_issuer_chain", 's'},
        {"sgx_cpu_svn", 'x'},
        {"sgx_has_einittoken_key", 'x'},
        {"sgx_has_provision_key", 'x'},
        {"sgx_is_mode64bit", 'x'},
        {"sgx_isv_extended_product_id", 'x'},
        {"sgx_isv_family_id", 'x'},
        {"sgx_pce_svn", 'x'},
        {"sgx_pck_crl", 's'},
        {"sgx_pf_gp_exit_info_enabled", 'x'},
        {"sgx_qe_id_info", 's'},
        {"sgx_qe_id_issuer_chain", 's'},
        {"sgx_root_ca_crl", 's'},
        {"sgx_tcb_info", 's'},
        {"sgx_tcb_issuer_chain", 's'},
        {"sgx_uses_kss", 'x'},
        {"signer_id", 'x'},
        {"tcb_date", 'D'},
        {"tcb_status", 'u'},
        {"ueid", 'x'},
        {"unique_id", 'x'},
        {"validity_from", 'D'},
        {"validity_until", 'D'}};
    std::map<std::string, char>::iterator itr;

    for (size_t i = 0; i < claims_length; i++)
    {
        itr = claims_format.find(claims[i].name);
        print_claims(
            i,
            (const char*)claims[i].name,
            (const uint8_t*)claims[i].value,
            claims[i].value_size,
            (const char)itr->second);
    }
}

oe_result_t dump_sgx_quote(
    const uint8_t* quote_buffer,
    const uint8_t* boundary,
    size_t boundary_size)
{
    oe_result_t result = OE_OK;

    sgx_quote_t* quote = (sgx_quote_t*)quote_buffer;
    sgx_report_body_t* report_body = (sgx_report_body_t*)&quote->report_body;
    sgx_quote_auth_data_t* quote_auth_data =
        (sgx_quote_auth_data_t*)quote->signature;
    sgx_report_body_t* qe_report_body =
        (sgx_report_body_t*)&quote_auth_data->qe_report_body;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};

    uint8_t* p = (uint8_t*)quote_auth_data;

    // Boundary check
    if (boundary_size <
        ((size_t)(p - boundary) + sizeof(sgx_quote_auth_data_t) + 2))
    {
        printf("Invalid evidence format. evidence_size=%zu\n", boundary_size);
        return OE_REPORT_PARSE_ERROR;
    }

    p += sizeof(sgx_quote_auth_data_t);
    qe_auth_data.size = read_uint16(p);
    p += 2;
    qe_auth_data.data = (uint8_t*)p;

    // Boundary check
    if (boundary_size <
        ((size_t)(p - boundary) + qe_auth_data.size + qe_cert_data.size + 6))
    {
        printf("Invalid evidence format. evidence_size=%zu\n", boundary_size);
        return OE_REPORT_PARSE_ERROR;
    }

    p += qe_auth_data.size;
    qe_cert_data.type = read_uint16(p);
    p += 2;
    qe_cert_data.size = read_uint32(p);
    p += 4;
    qe_cert_data.data = (uint8_t*)p;

    printf("    sgx_quote_t {\n");
    printf("        version: %d\n", quote->version);
    printf("        sign_type: %d\n", quote->sign_type);
    printf("        qe_svn: 0x%x\n", quote->qe_svn);
    printf("        pce_svn: 0x%x\n", quote->pce_svn);
    printf("        uuid (hex): ");
    oe_hex_dump(quote->uuid, OE_COUNTOF(quote->uuid));
    printf("        user_data (first_32_bytes == qe_id) (hex): ");
    oe_hex_dump(quote->user_data, OE_COUNTOF(quote->user_data));

    printf("        report_body {\n");
    printf("            cpusvn (hex): ");
    oe_hex_dump(report_body->cpusvn, OE_COUNTOF(report_body->cpusvn));
    printf("            miscselect: 0x%x\n", report_body->miscselect);
    printf("            isvextprodid (hex): ");
    oe_hex_dump(
        report_body->isvextprodid, OE_COUNTOF(report_body->isvextprodid));
    printf("            attributes (hex): ");
    oe_hex_dump(&report_body->attributes, sizeof(report_body->attributes));
    printf("            mrenclave (hex): ");
    oe_hex_dump(report_body->mrenclave, OE_COUNTOF(report_body->mrenclave));
    printf("            mrsigner (hex): ");
    oe_hex_dump(report_body->mrsigner, OE_COUNTOF(report_body->mrsigner));
    printf("            configid (hex): ");
    oe_hex_dump(report_body->configid, OE_COUNTOF(report_body->configid));
    printf("            isvprodid: 0x%x\n", report_body->isvprodid);
    printf("            isvsvn: 0x%x\n", report_body->isvsvn);
    printf("            configsvn: 0x%x\n", report_body->configsvn);
    printf("            isvfamilyid (hex): ");
    oe_hex_dump(report_body->isvfamilyid, OE_COUNTOF(report_body->isvfamilyid));
    printf("            report_data (hex): ");
    oe_hex_dump(&report_body->report_data, sizeof(report_body->report_data));
    printf("        } report_body\n");

    printf("        signature_len: %d\n", quote->signature_len);
    printf("        signature_data: {\n");
    printf("            sgx_quote_auth_data_t {\n");
    printf("                signature (hex): ");
    oe_hex_dump(
        &quote_auth_data->signature, sizeof(quote_auth_data->signature));
    printf("                attestation_key (hex): ");
    oe_hex_dump(
        &quote_auth_data->attestation_key,
        sizeof(quote_auth_data->attestation_key));

    printf("                qe_report_body {\n");
    printf("                    cpusvn (hex): ");
    oe_hex_dump(qe_report_body->cpusvn, OE_COUNTOF(qe_report_body->cpusvn));
    printf(
        "                    miscselect: 0x%x\n", qe_report_body->miscselect);
    printf("                    attributes (hex): ");
    oe_hex_dump(
        &qe_report_body->attributes, sizeof(qe_report_body->attributes));
    printf("                    mrenclave (hex): ");
    oe_hex_dump(
        qe_report_body->mrenclave, OE_COUNTOF(qe_report_body->mrenclave));
    printf("                    mrsigner (hex): ");
    oe_hex_dump(qe_report_body->mrsigner, OE_COUNTOF(qe_report_body->mrsigner));
    printf("                    isvprodid: 0x%x\n", qe_report_body->isvprodid);
    printf("                    isvsvn: 0x%x\n", qe_report_body->isvsvn);
    printf("                    report_data (hex): ");
    oe_hex_dump(
        &qe_report_body->report_data, sizeof(qe_report_body->report_data));
    printf("                } qe_report_body\n");

    printf("                qe_report_body_signature: ");
    oe_hex_dump(
        &quote_auth_data->qe_report_body_signature,
        sizeof(quote_auth_data->qe_report_body_signature));
    printf("            } sgx_quote_auth_data_t\n");
    printf("            qe_auth_data {\n");
    printf("                size: %d\n", qe_auth_data.size);
    printf("                data (hex): ");
    oe_hex_dump(qe_auth_data.data, qe_auth_data.size);
    printf("            } qe_auth_data\n");

    printf("            qe_cert_data {\n");
    printf("                type: 0x%x\n", qe_cert_data.type);
    printf("                size: %d\n", qe_cert_data.size);
    printf("                qe cert:\n");
    dump_certificate_chain(qe_cert_data.data, qe_cert_data.size, true);
    printf("            } qe_cert_data\n");
    printf("        } signature_data\n");
    printf("    } sgx_quote_t\n");

    return result;
}

oe_result_t dump_oe_report(const uint8_t* report, size_t report_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* header = (oe_report_header_t*)report;

    printf("\nOE Report:\n");
    printf("oe_report_header {\n");
    printf("    version: %d\n", header->version);
    printf("    report_type: %d\n", header->report_type);
    printf("    report_size: %zu\n", header->report_size);

    OE_CHECK_MSG(
        dump_sgx_quote(header->report, report, report_size),
        "Failed to dump OE report. Error: (%s)\n",
        oe_result_str(result));

    printf("} oe_report_header\n");

    result = OE_OK;

done:
    return result;
}

oe_result_t dump_oe_evidence(
    const oe_uuid_t& evidence_format,
    const uint8_t* evidence,
    size_t evidence_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (memcmp(&evidence_format, &_sgx_ecdsa_uuid, sizeof(oe_uuid_t)) == 0)
    {
        printf("\nOE Evidence:\n");

        OE_CHECK_MSG(
            dump_sgx_quote(evidence, evidence, evidence_size),
            "Failed to dump OE evidence. Error: (%s)\n",
            oe_result_str(result));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t dump_oe_endorsements(
    const uint8_t* endorsements_data,
    size_t endorsements_data_size)
{
    oe_result_t result = OE_OK;
    oe_sgx_endorsements_t endorsements;

    result = oe_parse_sgx_endorsements(
        (oe_endorsements_t*)endorsements_data,
        endorsements_data_size,
        &endorsements);
    if (result == OE_OK)
    {
        oe_sgx_endorsement_item endorsement_version =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_VERSION];
        log("Endorsement: Version:\n%d\n\n", *(endorsement_version.data));

        oe_sgx_endorsement_item tcb_info =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO];
        log("Endorsement: Revocation TCB Info:\n%s\n\n", tcb_info.data);

        oe_sgx_endorsement_item tcb_issuer_chain =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN];
        log("Endorsement: Revocation TCB Issuer Chain:\n");
        dump_certificate_chain(
            tcb_issuer_chain.data, tcb_issuer_chain.size, false);

        oe_sgx_endorsement_item crl_pck_cert =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT];
        log("Endorsement: CRL PCK Certificate:\n");
        if (crl_pck_cert.size >= OE_PEM_BEGIN_CRL_LEN &&
            memcmp(
                (const char*)crl_pck_cert.data,
                OE_PEM_BEGIN_CRL,
                OE_PEM_BEGIN_CRL_LEN) == 0)
            decode_crl_pem(crl_pck_cert.data, crl_pck_cert.size);
        else
            decode_crl_der(crl_pck_cert.data, crl_pck_cert.size);
        log("\n");

        oe_sgx_endorsement_item crl_pck_proc_ca =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA];
        log("Endorsement: CRL PCK Proc CA:\n");
        if (crl_pck_proc_ca.size >= OE_PEM_BEGIN_CRL_LEN &&
            memcmp(
                (const char*)crl_pck_proc_ca.data,
                OE_PEM_BEGIN_CRL,
                OE_PEM_BEGIN_CRL_LEN) == 0)
            decode_crl_pem(crl_pck_proc_ca.data, crl_pck_proc_ca.size);
        else
            decode_crl_der(crl_pck_proc_ca.data, crl_pck_proc_ca.size);
        log("\n");

        oe_sgx_endorsement_item crl_issuer_chain =
            endorsements
                .items[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT];
        log("Endorsement: CRL Issuer Chain:\n");
        dump_certificate_chain(
            crl_issuer_chain.data, crl_issuer_chain.size, false);

        oe_sgx_endorsement_item qe_id_info =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO];
        log("Endorsement: QE ID Info:\n%s\n\n", qe_id_info.data);

        oe_sgx_endorsement_item qe_id_issuer_chain =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN];
        log("Endorsement: QE ID Issuer Chain:\n");
        dump_certificate_chain(
            qe_id_issuer_chain.data, qe_id_issuer_chain.size, false);

        oe_sgx_endorsement_item creation_datetime =
            endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME];
        log("Endorsement: Creation Datetime:\n%s\n\n", creation_datetime.data);
    }
    return result;
}

oe_result_t verify_signer_id(
    const char* siging_public_key,
    size_t siging_public_key_size,
    uint8_t* signer_id,
    size_t signer_id_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t signer[OE_SIGNER_ID_SIZE];
    size_t signer_size = sizeof(signer);

    if (signer_id_size != OE_SIGNER_ID_SIZE)
    {
        printf("Invalid signer id size: %zu", signer_id_size);
        goto done;
    }

    OE_CHECK_MSG(
        oe_sgx_get_signer_id_from_public_key(
            siging_public_key, siging_public_key_size, signer, &signer_size),
        "Failed to get signer id from public key. Error: (%s)\n",
        oe_result_str(result));

    if (memcmp(signer, signer_id, signer_id_size) != 0)
    {
        printf("mrsigner is not equal!\n");
        for (size_t i = 0; i < signer_id_size; i++)
        {
            printf("0x%x - 0x%x\n", (uint8_t)signer[i], (uint8_t)signer_id[i]);
        }
        goto done;
    }
    result = OE_OK;

done:
    return result;
}

// This is the identity validation callback. A TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept a connection request.
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    printf("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    printf("identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        printf(
            "identity.security_version check failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.  In a real scenario,
    // custom id checking should be done here
    printf("identity->unique_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->unique_id[i]);

    printf("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);

    // verify signer id
    OE_CHECK_MSG(
        verify_signer_id(
            (char*)OEUTIL_ENC_PUBLIC_KEY,
            sizeof(OEUTIL_ENC_PUBLIC_KEY),
            identity->signer_id,
            sizeof(identity->signer_id)),
        "Failed to verify signer id. Error: (%s)\n",
        oe_result_str(result));

    printf("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

oe_result_t get_oe_report_from_certificate(
    const uint8_t* certificate_in_der,
    size_t certificate_in_der_length,
    uint8_t** report,
    size_t* report_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* report_buffer = nullptr;
    size_t report_buffer_size = 0;
    oe_cert_t certificate = {0};

    result = oe_cert_read_der(
        &certificate, certificate_in_der, certificate_in_der_length);
    if (result != OE_OK)
        return result;

    // find the extension
    result = oe_cert_find_extension(
        &certificate,
        X509_OID_FOR_NEW_QUOTE_STRING,
        &report_buffer,
        &report_buffer_size);

    if (result == OE_OK)
    {
        *report = report_buffer;
        *report_size = report_buffer_size;
    }
    else
    {
        free(report_buffer);
    }

    return result;
}

oe_result_t generate_certificate(
    oe_enclave_t* enclave,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    const char* certificate_filename,
    bool verify,
    bool verbose)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t ecall_result;
    uint8_t* report = nullptr;
    size_t report_size = 0;
    cert_t certificate = {0};

    log("========== Creating certificate with given private/public keys.\n");
    result = get_tls_cert_signed_with_key(
        enclave,
        &ecall_result,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        &certificate);

    if ((result != OE_OK) || (ecall_result != OE_OK))
    {
        printf(
            "Failed to create certificate. Enclave: %s, Host: %s\n",
            oe_result_str(ecall_result),
            oe_result_str(result));
        goto done;
    }
    if (certificate_filename)
    {
        result = output_file(
            certificate_filename, certificate.data, certificate.size);
        if (result != OE_OK)
        {
            printf(
                "Failed to open certificate file %s\n", certificate_filename);
            goto done;
        }
    }

    if (verbose)
    {
        printf("\n");
        dump_certificate(certificate.data, certificate.size);

        if (get_oe_report_from_certificate(
                certificate.data, certificate.size, &report, &report_size) ==
            OE_OK)
        {
            dump_oe_report(report, report_size);
        }
    }

    log("========== Got certificate = %p certificate_size = %zu\n",
        certificate.data,
        certificate.size);

    if (verify) // validate certificate
    {
        OE_CHECK_MSG(
            oe_verify_attestation_certificate(
                certificate.data,
                certificate.size,
                enclave_identity_verifier,
                nullptr),
            "Failed to verify certificate. result=%u (%s)\n",
            result,
            oe_result_str(result));

        log("========== Certificate verified\n\n");
    }

done:
    // deallcate resources
    free(certificate.data);

    fflush(stdout);
    return result;
}

oe_result_t generate_oe_report(
    oe_enclave_t* enclave,
    const char* report_filename,
    const char* endorsements_filename,
    bool verify,
    bool verbose)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = nullptr;
    oe_report_header_t* header = nullptr;
    sgx_quote_t* quote = nullptr;
    uint64_t quote_size = 0;

    log("========== Getting OE report\n");

    OE_CHECK_MSG(
        oe_get_report(
            enclave,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            nullptr, // opt_params must be null
            0,
            (uint8_t**)&remote_report,
            &report_size),
        "Failed to create OE report. Error: %s\n",
        oe_result_str(result));

    log("========== Got OE report, size = %zu\n\n", report_size);

    header = (oe_report_header_t*)remote_report;
    quote = (sgx_quote_t*)header->report;
    quote_size = header->report_size;

    // Write report to file
    if (report_filename)
    {
        OE_CHECK_MSG(
            output_file(report_filename, remote_report, report_size),
            "Failed to open report file %s\n",
            report_filename);
    }

    // Dump report
    printf("Generate OE report, report_size = %zu\n", report_size);

    if (verbose)
    {
        OE_CHECK_MSG(
            dump_oe_report(remote_report, report_size),
            "Failed to dump OE report. Error: (%s)\n",
            oe_result_str(result));
    }
    else
    {
        // Print basic info to console
        printf("QEID: ");
        oe_hex_dump(quote->user_data, 16);
        printf("CPU_SVN: ");
        oe_hex_dump(quote->report_body.cpusvn, SGX_CPUSVN_SIZE);
        printf("PCE_SVN: %02x\n", quote->pce_svn);
    }

    // Log endorsements
    if (endorsements_filename)
    {
        uint8_t* endorsements = nullptr;
        size_t endorsements_size = 0;

        OE_CHECK_MSG(
            oe_get_sgx_endorsements(
                (const uint8_t*)quote,
                quote_size,
                NULL,
                0,
                &endorsements,
                &endorsements_size),
            "Failed to get endorsements. Error: (%s)\n",
            oe_result_str(result));

        log("\n\n========== Got endorsements, size = %zu\n", endorsements_size);

        OE_CHECK_MSG(
            dump_oe_endorsements(endorsements, endorsements_size),
            "Failed to dump endorsements. Error: (%s)\n",
            oe_result_str(result));

        // Write endorsements
        OE_CHECK_MSG(
            output_file(endorsements_filename, endorsements, endorsements_size),
            "Failed to open endorsement file %s\n",
            endorsements_filename);

        oe_free_sgx_endorsements(endorsements);
    }

    if (verify) // Verify report
    {
        log("========== Verifying OE report\n");

        oe_report_t parsed_report;

        result = oe_verify_report(
            nullptr, remote_report, report_size, &parsed_report);

        if (result == OE_OK)
        {
            log("========== TCB is up-to-date\n");
        }
        else if (result == OE_TCB_LEVEL_INVALID)
        {
            log("========== Non-terminal TCB: 0x:%0x\n",
                parsed_report.verification_result);
        }
        else
        {
            OE_CHECK_MSG(
                result,
                "Failed to verify report. Error: (%s)\n",
                oe_result_str(result));
        }

        // verify signer id
        OE_CHECK_MSG(
            verify_signer_id(
                (char*)OEUTIL_ENC_PUBLIC_KEY,
                sizeof(OEUTIL_ENC_PUBLIC_KEY),
                parsed_report.identity.signer_id,
                sizeof(parsed_report.identity.signer_id)),
            "Failed to verify signer id. Error: (%s)\n",
            oe_result_str(result));

        log("========== OE report verified\n\n");
    }
    printf("generate_oe_report succeeded, more info in log file.\n");

    result = OE_OK;

done:
    oe_free_report(remote_report);

    return result;
}

oe_result_t generate_oe_evidence(
    oe_enclave_t* enclave,
    const oe_uuid_t evidence_format,
    const char* evidence_filename,
    const char* endorsements_filename,
    bool verify,
    bool verbose)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t evidence_size = 0;
    uint8_t evidence[MAX_BUFFER_SIZE];
    size_t endorsements_size = 0;
    uint8_t endorsements[MAX_BUFFER_SIZE];

    log("========== Getting OE evidence\n");

    // only retrieve endorsements when need to output endorsements file or
    // verify envidence
    if (endorsements_filename || verify)
    {
        get_plugin_evidence(
            enclave,
            &result,
            evidence_format,
            evidence,
            sizeof(evidence),
            &evidence_size,
            endorsements,
            sizeof(endorsements),
            &endorsements_size);
        OE_CHECK_MSG(
            result,
            "Failed to create OE evidence. Error: %s\n",
            oe_result_str(result));
    }
    else
    {
        get_plugin_evidence(
            enclave,
            &result,
            evidence_format,
            evidence,
            sizeof(evidence),
            &evidence_size,
            NULL,
            0,
            NULL);
        OE_CHECK_MSG(
            result,
            "Failed to create OE evidence. Error: %s\n",
            oe_result_str(result));

        OE_UNUSED(endorsements);
        OE_UNUSED(endorsements_size);
    }

    log("========== Got OE evidence, size = %zu\n\n", evidence_size);

    // Write evidence to file
    if (evidence_filename)
    {
        OE_CHECK_MSG(
            output_file(evidence_filename, evidence, evidence_size),
            "Failed to open evidence file %s\n",
            evidence_filename);
    }

    // Dump evidence
    printf("Generated OE evidence, evidence_size = %zu\n", evidence_size);
    if (verbose)
    {
        OE_CHECK_MSG(
            dump_oe_evidence(evidence_format, evidence, evidence_size),
            "Failed to dump OE evidence. Error: (%s)\n",
            oe_result_str(result));
    }
    else if (memcmp(&evidence_format, &_sgx_ecdsa_uuid, sizeof(oe_uuid_t)) == 0)
    {
        // Print basic info to console
        sgx_quote_t* quote = (sgx_quote_t*)evidence;
        printf("QEID: ");
        oe_hex_dump(quote->user_data, 16);
        printf("CPU_SVN: ");
        oe_hex_dump(quote->report_body.cpusvn, SGX_CPUSVN_SIZE);
        printf("PCE_SVN: %02x\n", quote->pce_svn);
    }

    // Log endorsements
    if (endorsements_filename || verify)
    {
        log("========== Got endorsements, size = %zu\n", endorsements_size);

        OE_CHECK_MSG(
            dump_oe_endorsements(endorsements, endorsements_size),
            "Failed to dump endorsements. Error: (%s)\n",
            oe_result_str(result));

        // Write endorsements
        if (endorsements_filename)
        {
            OE_CHECK_MSG(
                output_file(
                    endorsements_filename, endorsements, endorsements_size),
                "Failed to open endorsement file %s\n",
                endorsements_filename);
        }
    }

    if (verify) // Verify evidence
    {
        log("========== Verifying OE evidence\n");

        oe_claim_t* claims = NULL;
        size_t claims_length = 0;
        const oe_claim_t* claim;
        oe_result_t _verify_evidence_result;
        std::vector<oe_policy_t> policies = {};
        uint8_t* endorsements_buffer = endorsements;
        size_t endorsements_buffer_size = endorsements_size;
        if (_parameters.baseline != NULL)
        {
            oe_policy_t policy = {
                OE_POLICY_ENDORSEMENTS_BASELINE,
                (void*)_parameters.baseline,
                strlen(_parameters.baseline) + 1};
            policies.emplace_back(policy);

            // Endorsements need to be recreated as endorsements baseline is
            // specified
            endorsements_buffer = NULL;
            endorsements_buffer_size = 0;
        }

        OE_CHECK(oe_verifier_initialize());

        OE_CHECK_NO_TCB_LEVEL_MSG(
            _verify_evidence_result,
            oe_verify_evidence(
                &evidence_format,
                evidence,
                evidence_size,
                endorsements_buffer,
                endorsements_buffer_size,
                policies.data(),
                policies.size(),
                &claims,
                &claims_length),
            "Failed to verify evidence. Error: (%s)\n",
            oe_result_str(result));

        // verify signer id
        claim = find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID);
        if (claim == nullptr)
        {
            printf("cannot find oe_claim: %s.\n", OE_CLAIM_SIGNER_ID);
            goto done;
        }
        OE_CHECK_MSG(
            verify_signer_id(
                (char*)OEUTIL_ENC_PUBLIC_KEY,
                sizeof(OEUTIL_ENC_PUBLIC_KEY),
                claim->value,
                claim->value_size),
            "Failed to verify signer id. Error: (%s)\n",
            oe_result_str(result));

        log("========== OE evidence verified.\n\n");

        if (verbose)
            dump_claims(claims, claims_length);

        OE_CHECK(oe_free_claims(claims, claims_length));
        OE_CHECK(oe_verifier_shutdown());

        result = _verify_evidence_result;
    }
    else
    {
        result = OE_OK;
    }
    printf("generate_oe_evidence succeeded, more info in log file.\n");

done:
    return result;
}

// Get full path of oeutil running executable, then get enclave filename by:
// In linux, replace "<path>/oeutil" with "<path>/oeutil_enc.signed".
// In windows, replace "<path>/oeutil.exe" with "<path>/oeutil_enc.signed".
static char* _get_enclave_filename()
{
    char* enclave_filename = nullptr;
    char path[OE_PATH_MAX];
    size_t path_size = 0;
    size_t enclave_filename_size = 0;

#if defined(__linux__)
    path_size += (size_t)readlink("/proc/self/exe", path, OE_PATH_MAX);
#elif defined(_WIN32)
    path_size += (size_t)GetModuleFileName(nullptr, path, OE_PATH_MAX);
    path_size -= strlen(".exe");
#endif

    if (path_size < 0 || path_size >= OE_PATH_MAX)
    {
        printf("Failed to read enclave full path.\n");
        goto done;
    }
    path[path_size] = '\0';
    enclave_filename_size = path_size + sizeof(ENCLAVE_FILENAME_SUFFIX);
    enclave_filename = (char*)malloc(enclave_filename_size);

    if (enclave_filename == nullptr)
    {
        printf("Failed to malloc enclave_filename.\n");
        goto done;
    }
    snprintf(
        enclave_filename,
        enclave_filename_size,
        "%s%s",
        path,
        ENCLAVE_FILENAME_SUFFIX);

    // Verify enclave file is valid
    FILE* fp;
    fopen_s(&fp, enclave_filename, "rb");
    if (!fp)
    {
        printf("Enclave file does not exist: %s.\n", enclave_filename);
        goto done;
    }
    else
        fclose(fp);

done:
    return enclave_filename;
}

int _parse_args(int argc, const char* argv[])
{
    // clear parameters memory
    memset(&_parameters, 0, sizeof(_parameters));

    // save
    _parameters.generate_certificate = false;
    _parameters.generate_legacy_report_remote = false;
    _parameters.generate_sgx_ecdsa = false;
    _parameters.generate_sgx_epid_linkable = false;
    _parameters.generate_sgx_epid_unlinkable = false;
    _parameters.out_filename = nullptr;
    _parameters.endorsements_filename = nullptr;
    _parameters.log_filename = DEFAULT_LOG_FILE;
#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
    _parameters.override_pubkey_filename = nullptr;
#endif
    _parameters.quote_proc = "";
    _parameters.verify = false;
    _parameters.verbose = false;

    int i = 2; // current index

    if (argc == 3 && (strcasecmp(INPUT_PARAM_OPTION_HELP, argv[i]) == 0 ||
                      strcasecmp(SHORT_INPUT_PARAM_OPTION_HELP, argv[i]) == 0))
    {
        _display_help(argv[0]);
        return 0;
    }

    if (argc < 4)
    {
        _display_help(argv[0]);
        return 1;
    }

    while (i < argc)
    {
        if (strcasecmp(INPUT_PARAM_OPTION_FORMAT, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_FORMAT, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            if (strcasecmp(INPUT_PARAM_OPTION_CERT, argv[i + 1]) == 0)
            {
                if (argc < i + 4)
                    break;

                _parameters.generate_certificate = true;
                _parameters.private_key_filename = argv[i + 2];
                _parameters.public_key_filename = argv[i + 3];
                i += 4;
            }
            else if (
                strcasecmp(
                    INPUT_PARAM_OPTION_LEGACY_REPORT_REMOTE, argv[i + 1]) == 0)
            {
                _parameters.generate_legacy_report_remote = true;
                i += 2;
            }
            else if (strcasecmp(INPUT_PARAM_OPTION_SGX_ECDSA, argv[i + 1]) == 0)
            {
                _parameters.generate_sgx_ecdsa = true;
                i += 2;
            }
            else if (
                strcasecmp(INPUT_PARAM_OPTION_SGX_EPID_LINKABLE, argv[i + 1]) ==
                0)
            {
                _parameters.generate_sgx_epid_linkable = true;
                i += 2;
            }
            else if (
                strcasecmp(
                    INPUT_PARAM_OPTION_SGX_EPID_UNLINKABLE, argv[i + 1]) == 0)
            {
                _parameters.generate_sgx_epid_unlinkable = true;
                i += 2;
            }
            else
            {
                printf("Invalid format: %s\n\n", argv[i + 1]);
                break;
            }
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_QUOTE_PROC, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_QUOTE_PROC, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _parameters.quote_proc = argv[i + 1];
            if (strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _parameters.quote_proc) !=
                    0 &&
                strcasecmp(
                    INPUT_PARAM_QUOTE_OUT_OF_PROC, _parameters.quote_proc) != 0)
            {
                printf(
                    "Please use 'in' or 'out' with %s.\n",
                    INPUT_PARAM_OPTION_QUOTE_PROC);
                return 1;
            }
            i += 2;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME, argv[i]) ==
                0 ||
            strcasecmp(
                SHORT_INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _parameters.endorsements_filename = argv[i + 1];
            i += 2;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_OUT_FILE, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_OUT_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _parameters.out_filename = argv[i + 1];
            i += 2;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_VERIFY, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_VERIFY, argv[i]) == 0)
        {
            _parameters.verify = true;
            i++;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_LOG_FILE, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_LOG_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _parameters.log_filename = argv[i + 1];
            i += 2;
        }
#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
        else if (strcasecmp(INPUT_PARAM_OPTION_ROOT_PUB_KEY, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _parameters.override_pubkey_filename = argv[i + 1];
            i += 2;
        }
#endif
#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
        else if (strcasecmp(INPUT_PARAM_OPTION_BYPASS_DATE, argv[i]) == 0)
        {
            _should_skip_date_check = true;
            i++;
        }
#endif
        else if (
            strcasecmp(INPUT_PARAM_OPTION_BASELINE, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_BASELINE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _parameters.baseline = argv[i + 1];
            i += 2;
        }
        else if (strcasecmp(INPUT_PARAM_OPTION_VERBOSE, argv[i]) == 0)
        {
            _parameters.verbose = true;
            i++;
        }
        else
        {
            printf("Invalid option: %s\n\n", argv[i]);
            _display_help(argv[0]);
            return 1;
        }
    }

    if (i < argc)
    {
        printf("%s has invalid number of parameters.\n\n", argv[i]);
        _display_help(argv[0]);
        return 1;
    }

    if (_parameters.generate_certificate +
            _parameters.generate_legacy_report_remote +
            _parameters.generate_sgx_ecdsa +
            _parameters.generate_sgx_epid_linkable +
            _parameters.generate_sgx_epid_unlinkable !=
        1)
    {
        printf("Please specify to generate a certificate, a report, or "
               "evidence in SGX_ECDSA format.\n");
        return 1;
    }

    return 0;
}

oe_result_t _process_parameters(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;

#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
    size_t override_public_key_size = 0;
    uint8_t* override_public_key = nullptr;
#endif

#if defined(__linux__)
    char* sgx_aesm_env = getenv(SGX_AESM_ADDR);

    // For Linux, if "SGX_AESM_ADDR" not set and out-of-proc is required, set
    // "SGX_AESM_ADDR" to "1" and unset after process finishes
    if (sgx_aesm_env == nullptr)
    {
        if (strcasecmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _parameters.quote_proc) ==
                0 &&
            setenv(SGX_AESM_ADDR, "1", 1) != 0)
        {
            printf("Failed to set environment variable 'SGX_AESM_ADDR'\n");
            goto done;
        }
    }
    // if "SGX_AESM_ADDR" is set and in-proc is required, unset it during the
    // process and reset it to its original value after process finishes
    else if (
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _parameters.quote_proc) == 0 &&
        unsetenv(SGX_AESM_ADDR) != 0)
    {
        printf("Failed to unset environment variable 'SGX_AESM_ADDR'\n");
        goto done;
    }
#elif defined(_WIN32)
    char sgx_aesm_env[SGX_AESM_ADDR_MAXSIZE];
    int env_size = GetEnvironmentVariableA(
        SGX_AESM_ADDR, sgx_aesm_env, SGX_AESM_ADDR_MAXSIZE);

    if ((env_size == 0 && GetLastError() != ERROR_ENVVAR_NOT_FOUND) ||
        env_size >= SGX_AESM_ADDR_MAXSIZE)
    {
        printf("Failed to read environment variable 'SGX_AESM_ADDR'\n");
        goto done;
    }

    // For Windows, out-of-proc is not tested as extra dependencies required
    if (strcasecmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _parameters.quote_proc) == 0)
    {
        printf("In-proc quoting is by default on Windows. Please use in-proc "
               "quoting\n");
        goto done;
    }
    // if "SGX_AESM_ADDR" is set and in-proc is required, unset it during the
    // process and reset it to its original value after process finishes
    else if (
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _parameters.quote_proc) == 0 &&
        env_size != 0 && SetEnvironmentVariableA(SGX_AESM_ADDR, nullptr) == 0)
    {
        printf("Failed to unset environment variable 'SGX_AESM_ADDR'\n");
        goto done;
    }
#endif

#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
    // Load public key and assign it to _trusted_root_key_pem
    if (_parameters.override_pubkey_filename)
    {
        OE_CHECK(_read_key(
            _parameters.override_pubkey_filename,
            &override_public_key,
            &override_public_key_size));
        _trusted_root_key_pem = (const char*)override_public_key;
    }
#endif

    if (_parameters.generate_certificate)
    {
        size_t private_key_size;
        uint8_t* private_key;
        size_t public_key_size;
        uint8_t* public_key;

        // read private key (pem format)
        OE_CHECK(_read_key(
            _parameters.private_key_filename, &private_key, &private_key_size));
        OE_CHECK(_read_key(
            _parameters.public_key_filename, &public_key, &public_key_size));
        OE_CHECK(generate_certificate(
            enclave,
            private_key,
            private_key_size,
            public_key,
            public_key_size,
            _parameters.out_filename,
            _parameters.verify,
            _parameters.verbose));
    }
    else if (_parameters.generate_legacy_report_remote)
    {
        OE_CHECK(generate_oe_report(
            enclave,
            _parameters.out_filename,
            _parameters.endorsements_filename,
            _parameters.verify,
            _parameters.verbose));
    }
    else if (_parameters.generate_sgx_ecdsa)
    {
        OE_CHECK(generate_oe_evidence(
            enclave,
            _sgx_ecdsa_uuid,
            _parameters.out_filename,
            _parameters.endorsements_filename,
            _parameters.verify,
            _parameters.verbose));
    }
    else if (_parameters.generate_sgx_epid_linkable)
    {
        OE_CHECK(generate_oe_evidence(
            enclave,
            _sgx_epid_linkable_uuid,
            _parameters.out_filename,
            _parameters.endorsements_filename,
            false,
            _parameters.verbose));
    }
    else if (_parameters.generate_sgx_epid_unlinkable)
    {
        OE_CHECK(generate_oe_evidence(
            enclave,
            _sgx_epid_unlinkable_uuid,
            _parameters.out_filename,
            _parameters.endorsements_filename,
            false,
            _parameters.verbose));
    }

    result = OE_OK;

done:

#if defined(__linux__)
    if (sgx_aesm_env == nullptr)
    {
        if (strcasecmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _parameters.quote_proc) ==
                0 &&
            unsetenv(SGX_AESM_ADDR) != 0)
        {
            printf(
                "Failed to unset environment variable 'SGX_AESM_ADDR', please "
                "manually unset it\n");
            result = OE_FAILURE;
        }
    }
    else if (
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _parameters.quote_proc) == 0 &&
        setenv(SGX_AESM_ADDR, sgx_aesm_env, 1) != 0)
    {
        printf(
            "Failed to reset environment variable 'SGX_AESM_ADDR', please "
            "manually reset it as %s\n",
            sgx_aesm_env);
        result = OE_FAILURE;
    }
#elif defined(_WIN32)
    if (env_size != 0 &&
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _parameters.quote_proc) == 0)
    {
        if (SetEnvironmentVariableA(SGX_AESM_ADDR, sgx_aesm_env) == 0)
        {
            printf(
                "Failed to reset environment variable 'SGX_AESM_ADDR', please "
                "manually reset it as %s\n",
                sgx_aesm_env);
            result = OE_FAILURE;
        }
    }
#endif
    return result;
}

int oeutil_generate_evidence(int argc, const char* argv[])
{
    int ret = 0;
    printf("NOTICE: oeutil generate-evidence is purely a debugging utility and "
           "not suitable for production use.\n\n");
    if (!oe_sgx_has_quote_provider())
    {
        fprintf(
            stderr, "FAILURE: DCAP libraries must be present for this test.\n");
        return 1;
    }

    oe_result_t result;
    oe_enclave_t* enclave = nullptr;
    char* enclave_filename = nullptr;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "oeutil generate-evidence is not supported in simulation mode.\n");
        goto done;
    }

    enclave_filename = _get_enclave_filename();
    if (enclave_filename == nullptr)
    {
        printf("Failed to get enclave filename.\n");
        goto done;
    }

    ret = _parse_args(argc, argv);
    if (ret != 0)
        goto done;

    if ((result = oe_create_oeutil_enclave(
             enclave_filename,
             OE_ENCLAVE_TYPE_AUTO,
             OE_ENCLAVE_FLAG_DEBUG,
             nullptr,
             0,
             &enclave)) != OE_OK)
    {
        printf(
            "Failed to create enclave. result=%u (%s)\n",
            result,
            oe_result_str(result));
        ret = 1;
        goto done;
    }

    // Create log file
#ifdef _WIN32
    fopen_s(&log_file, _parameters.log_filename, "w");
#else
    log_file = fopen(_parameters.log_filename, "w");
#endif
    if (!log_file)
    {
        printf("Failed to open log file %s\n", _parameters.log_filename);
        ret = 1;
        goto done;
    }

    set_log_callback();

    if ((result = _process_parameters(enclave)) != OE_OK)
    {
        printf(
            "Failed to process parameters. Error: %s\n", oe_result_str(result));
        ret = 1;
        goto done;
    }

    result = oe_terminate_enclave(enclave);
done:

    free(enclave_filename);
    return ret;
}
