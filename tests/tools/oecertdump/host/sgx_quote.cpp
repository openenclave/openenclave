// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgx_quote.h"

#include <ctype.h>
#include <openenclave/host.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/tests.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oecertdump_u.h"

#if defined(__linux__)
#include <dlfcn.h>
#else
#include <openssl/applink.c>
#endif

#include "../../../../common/sgx/collateral.h"
#include "../../../../common/sgx/quote.h"
#include "../../../../host/sgx/sgxquoteprovider.h"

#ifdef OE_LINK_SGX_DCAP_QL

extern FILE* log_file;

#define OE_PEM_BEGIN_CERTIFICATE "-----BEGIN CERTIFICATE-----"
#define OE_PEM_BEGIN_CERTIFICATE_LEN (sizeof(OE_PEM_BEGIN_CERTIFICATE) - 1)
#define OE_PEM_END_CERTIFICATE "-----END CERTIFICATE-----"
#define OE_PEM_END_CERTIFICATE_LEN (sizeof(OE_PEM_END_CERTIFICATE) - 1)
#define SGX_EXTENSION_OID_STR "1.2.840.113741.1.13.1"

void log(const char* fmt, ...)
{
    char message[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    // ensure buf is always null-terminated
    message[sizeof(message) - 1] = 0;

    if (log_file)
    {
        fprintf(log_file, "%s", message);
    }
    else
    {
        printf("%s", message);
    }
}

void output_certificate(const uint8_t* data, size_t data_len)
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

void decode_crl_pem(const uint8_t* data, size_t data_len)
{
    X509_CRL* x509;
    BIO* input = BIO_new_mem_buf(data, (int)data_len);
    x509 = PEM_read_bio_X509_CRL(input, NULL, NULL, NULL);
    if (x509)
        X509_CRL_print_fp(log_file, x509);
    BIO_free_all(input);
}

void parse_certificate_extension(const uint8_t* data, size_t data_len)
{
    oe_result_t result = OE_FAILURE;
    oe_cert_chain_t cert_chain = {0};
    oe_cert_t leaf_cert = {0};
    ParsedExtensionInfo extension_info = {{0}};
    size_t buffer_size = 1024;
    uint8_t* buffer = NULL;

    // get leaf cert to parse sgx extension
    oe_cert_chain_read_pem(&cert_chain, data, data_len);
    oe_cert_chain_get_leaf_cert(&cert_chain, &leaf_cert);

    // Try parsing the extensions.
    buffer = (uint8_t*)malloc(buffer_size);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);
    result =
        ParseSGXExtensions(&leaf_cert, buffer, &buffer_size, &extension_info);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        free(buffer);
        buffer = (uint8_t*)malloc(buffer_size);
        if (buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);
        result = ParseSGXExtensions(
            &leaf_cert, buffer, &buffer_size, &extension_info);
    }
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
    printf(
        "        opt_dynamic_platform: %s\n",
        extension_info.opt_dynamic_platform ? "true" : "false");
    printf(
        "        opt_cached_keys: %s\n",
        extension_info.opt_cached_keys ? "true" : "false");
    printf("    } qe cert extension \n");
done:
    free(buffer);
    oe_cert_chain_free(&cert_chain);
    oe_cert_free(&leaf_cert);
}

void output_certificate_chain(
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

// DCAP client (libdcap_quoteprov) log callback to this function.
void oecertdump_quote_provider_log(
    sgx_ql_log_level_t level,
    const char* message)
{
    const char* level_string = level == 0 ? "ERROR" : "INFO";

    log("[%s]: %s\n", level_string, message);
}

// Set DCAP client (libdcap_quoteprov) log callback
void set_log_callback()
{
#if defined(__linux__)
    extern oe_sgx_quote_provider_t provider;

    // Initialize quote provider and set log callback
    oe_initialize_quote_provider();

    sgx_ql_set_logging_function_t set_log_fcn =
        (sgx_ql_set_logging_function_t)dlsym(
            provider.handle, "sgx_ql_set_logging_function");
    if (set_log_fcn != nullptr)
    {
        set_log_fcn(oecertdump_quote_provider_log);
    }
#endif
}

OE_INLINE uint16_t read_uint16(const uint8_t* p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

OE_INLINE uint32_t read_uint32(const uint8_t* p)
{
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

oe_result_t output_sgx_report(const uint8_t* report, size_t report_size)
{
    oe_result_t result = OE_OK;
    oe_report_header_t* header = (oe_report_header_t*)report;
    sgx_quote_t* quote = (sgx_quote_t*)header->report;
    sgx_report_body_t* report_body = (sgx_report_body_t*)&quote->report_body;
    sgx_quote_auth_data_t* quote_auth_data =
        (sgx_quote_auth_data_t*)quote->signature;
    sgx_report_body_t* qe_report_body =
        (sgx_report_body_t*)&quote_auth_data->qe_report_body;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};

    uint8_t* p = (uint8_t*)quote_auth_data;

    // Boundary check
    if (report_size <
        ((size_t)(p - report) + sizeof(sgx_quote_auth_data_t) + 2))
    {
        printf("Invalid report format. report_size=%zu\n", report_size);
        return OE_REPORT_PARSE_ERROR;
    }

    p += sizeof(sgx_quote_auth_data_t);
    qe_auth_data.size = read_uint16(p);
    p += 2;
    qe_auth_data.data = (uint8_t*)p;

    // Boundary check
    if (report_size <
        ((size_t)(p - report) + qe_auth_data.size + qe_cert_data.size + 6))
    {
        printf("Invalid report format. report_size=%zu\n", report_size);
        return OE_REPORT_PARSE_ERROR;
    }

    p += qe_auth_data.size;
    qe_cert_data.type = read_uint16(p);
    p += 2;
    qe_cert_data.size = read_uint32(p);
    p += 4;
    qe_cert_data.data = (uint8_t*)p;

    printf("\nOE Report:\n");
    printf("oe_report_header {\n");
    printf("    version: %d\n", header->version);
    printf("    report_type: %d\n", header->report_type);
    printf("    report_size: %zu\n", header->report_size);

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
    printf("            attributes (hex): ");
    oe_hex_dump(&report_body->attributes, sizeof(report_body->attributes));
    printf("            mrenclave (hex): ");
    oe_hex_dump(report_body->mrenclave, sizeof(report_body->mrenclave));
    printf("            mrsigner (hex): ");
    oe_hex_dump(report_body->mrsigner, sizeof(report_body->mrsigner));
    printf("            isvprodid: 0x%x\n", report_body->isvprodid);
    printf("            isvsvn: 0x%x\n", report_body->isvsvn);
    printf("            report_data (hex): ");
    oe_hex_dump(&report_body->report_data, sizeof(report_body->report_data));
    printf("        } report_body\n");

    printf("        signature_len: %d\n", quote->signature_len);
    printf("        sgx_quote_auth_data_t {\n");
    printf("            signature (hex): ");
    oe_hex_dump(
        &quote_auth_data->signature, sizeof(quote_auth_data->signature));
    printf("            attestation_key (hex): ");
    oe_hex_dump(
        &quote_auth_data->attestation_key,
        sizeof(quote_auth_data->attestation_key));

    printf("            qe_report_body {\n");
    printf("                cpusvn (hex): ");
    oe_hex_dump(qe_report_body->cpusvn, OE_COUNTOF(qe_report_body->cpusvn));
    printf("                miscselect: 0x%x\n", qe_report_body->miscselect);
    printf("                attributes (hex): ");
    oe_hex_dump(
        &qe_report_body->attributes, sizeof(qe_report_body->attributes));
    printf("                mrenclave (hex): ");
    oe_hex_dump(qe_report_body->mrenclave, sizeof(qe_report_body->mrenclave));
    printf("                mrsigner (hex): ");
    oe_hex_dump(qe_report_body->mrsigner, sizeof(qe_report_body->mrsigner));
    printf("                isvprodid: 0x%x\n", qe_report_body->isvprodid);
    printf("                isvsvn: 0x%x\n", qe_report_body->isvsvn);
    printf("                report_data (hex): ");
    oe_hex_dump(
        &qe_report_body->report_data, sizeof(qe_report_body->report_data));
    printf("            } qe_report_body\n");

    printf("        qe_report_body_signature: ");
    oe_hex_dump(
        &quote_auth_data->qe_report_body_signature,
        sizeof(quote_auth_data->qe_report_body_signature));
    printf("        } sgx_quote_auth_data_t\n");
    printf("    } sgx_quote_t\n");
    printf("    qe_auth_data {\n");
    printf("        size: %d\n", qe_auth_data.size);
    printf("        data (hex): ");
    oe_hex_dump(qe_auth_data.data, qe_auth_data.size);
    printf("    } qe_auth_data\n");

    printf("    qe_cert_data {\n");
    printf("        type: 0x%x\n", qe_cert_data.type);
    printf("        size: %d\n", qe_cert_data.size);
    printf("        qe cert:\n");
    output_certificate_chain(qe_cert_data.data, qe_cert_data.size, true);
    printf("    } qe_cert_data\n");

    printf("} oe_report_header\n");

    return result;
}

oe_result_t generate_sgx_report(oe_enclave_t* enclave, bool verbose)
{
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = nullptr;
    oe_report_header_t* header = nullptr;
    sgx_quote_t* quote = nullptr;
    uint64_t quote_size = 0;

    log("========== Getting report\n");

    oe_result_t result = oe_get_report(
        enclave,
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        nullptr, // opt_params must be null
        0,
        (uint8_t**)&remote_report,
        &report_size);
    if (result == OE_OK)
    {
        log("========== Got report, size = %zu\n\n", report_size);

        header = (oe_report_header_t*)remote_report;
        quote = (sgx_quote_t*)header->report;
        quote_size = header->report_size;

        log("CPU_SVN: '");
        for (uint64_t n = 0; n < SGX_CPUSVN_SIZE; n++)
        {
            log("%02x", quote->report_body.cpusvn[n]);
        }
        log("'\nQEID: '");
        for (uint64_t n = 0; n < 16; n++)
        {
            log("%02x", quote->user_data[n]);
        }
        log("'\n");

        // Print endorsements
        {
            uint8_t* endorsements_data = nullptr;
            size_t endorsements_data_size = 0;

            result = oe_get_sgx_endorsements(
                (const uint8_t*)quote,
                quote_size,
                &endorsements_data,
                &endorsements_data_size);
            if (result != OE_OK)
            {
                log("ERROR: Failed to get endorsements\n");
                goto exit;
            }

            log("\n\n========== Got endorsements, size = %zu\n",
                endorsements_data_size);
            oe_sgx_endorsements_t endorsements;
            result = oe_parse_sgx_endorsements(
                (oe_endorsements_t*)endorsements_data,
                endorsements_data_size,
                &endorsements);

            oe_sgx_endorsement_item endorsement_version =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_VERSION];
            log("Endorsement: Version:\n%d\n\n", *(endorsement_version.data));

            oe_sgx_endorsement_item tcb_info =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO];
            log("Endorsement: Revocation TCB Info:\n%s\n\n", tcb_info.data);

            oe_sgx_endorsement_item tcb_issuer_chain =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN];
            log("Endorsement: Revocation TCB Issuer Chain:\n");
            output_certificate_chain(
                tcb_issuer_chain.data, tcb_issuer_chain.size, false);

            oe_sgx_endorsement_item crl_pck_cert =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT];
            log("Endorsement: CRL PCK Certificate:\n");
            decode_crl_pem(crl_pck_cert.data, crl_pck_cert.size);
            log("\n");

            oe_sgx_endorsement_item crl_pck_proc_ca =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA];
            log("Endorsement: CRL PCK Proc CA:\n");
            decode_crl_pem(crl_pck_proc_ca.data, crl_pck_proc_ca.size);
            log("\n");

            oe_sgx_endorsement_item crl_issuer_chain =
                endorsements
                    .items[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT];
            log("Endorsement: CRL Issuer Chain:\n");
            output_certificate_chain(
                crl_issuer_chain.data, crl_issuer_chain.size, false);

            oe_sgx_endorsement_item qe_id_info =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO];
            log("Endorsement: QE ID Info:\n%s\n\n", qe_id_info.data);

            oe_sgx_endorsement_item qe_id_issuer_chain =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN];
            log("Endorsement: QE ID Issuer Chain:\n");
            output_certificate_chain(
                qe_id_issuer_chain.data, qe_id_issuer_chain.size, false);

            oe_sgx_endorsement_item creation_datetime =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME];
            log("Endorsement: Creation Datetime:\n%s\n\n",
                creation_datetime.data);

            oe_free_sgx_endorsements(endorsements_data);
        }

        // Verify report
        {
            log("========== Verifying report\n");

            oe_report_t parsed_report;
            result = oe_verify_report(
                nullptr, remote_report, report_size, &parsed_report);
            if (verbose)
            {
                output_sgx_report(remote_report, report_size);
            }
            else
            {
                // Print basic collaterl info to console
                printf("QEID: ");
                oe_hex_dump(quote->user_data, 16);
                printf("CPU_SVN: ");
                oe_hex_dump(quote->report_body.cpusvn, SGX_CPUSVN_SIZE);
                printf("PCE_SVN: %02x\n", quote->pce_svn);
            }

            if (result != OE_OK)
            {
                log("Failed to verify report. result=%u (%s)\n",
                    result,
                    oe_result_str(result));

                printf(
                    "oe_verify_report failure (%s)\n", oe_result_str(result));

                goto exit;
            }
            else
            {
                log("========== Report verified\n\n");
            }
        }
    }
    else
    {
        log("Failed to create report. Error: %s\n", oe_result_str(result));
    }

exit:
    if (remote_report)
        oe_free_report(remote_report);

    return result;
}

oe_result_t get_sgx_report_from_certificate(
    const uint8_t* certificate_in_der,
    size_t certificate_in_der_length,
    uint8_t** report,
    size_t* report_size)
{
    oe_result_t result = OE_OK;
    uint8_t* report_buffer = nullptr;
    size_t report_buffer_size = certificate_in_der_length;
    oe_cert_t certificate = {0};

    result = oe_cert_read_der(
        &certificate, certificate_in_der, certificate_in_der_length);
    if (result != OE_OK)
        return result;

    report_buffer = (uint8_t*)malloc(report_buffer_size);
    if (!report_buffer)
        return OE_OUT_OF_MEMORY;

    // find the extension
    result = oe_cert_find_extension(
        &certificate,
        X509_OID_FOR_QUOTE_STRING,
        report_buffer,
        &report_buffer_size);

    if (result == OE_OK)
    {
        *report = report_buffer;
        *report_size = report_buffer_size;
    }
    else
    {
        if (!report_buffer)
            free(report_buffer);
    }

    return result;
}

#endif // OE_LINK_SGX_DCAP_QL
