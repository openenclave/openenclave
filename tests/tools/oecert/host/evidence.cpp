// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "evidence.h"

#include <ctype.h>
#include <openenclave/attestation/verifier.h>
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
#include "oecert_u.h"

#if defined(__linux__)
#include <dlfcn.h>
#else
#include <openssl/applink.c>
#endif

#include "../../../../common/attest_plugin.h"
#include "../../../../common/sgx/collateral.h"
#include "../../../../common/sgx/quote.h"
#include "../../../../host/sgx/sgxquoteprovider.h"

extern FILE* log_file;

#define OE_PEM_BEGIN_CERTIFICATE "-----BEGIN CERTIFICATE-----"
#define OE_PEM_BEGIN_CERTIFICATE_LEN (sizeof(OE_PEM_BEGIN_CERTIFICATE) - 1)
#define OE_PEM_END_CERTIFICATE "-----END CERTIFICATE-----"
#define OE_PEM_END_CERTIFICATE_LEN (sizeof(OE_PEM_END_CERTIFICATE) - 1)
#define SGX_EXTENSION_OID_STR "1.2.840.113741.1.13.1"
#define MAX_BUFFER_SIZE 65536

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
    free(buffer);
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

void dump_claims(const oe_claim_t* claims, size_t claims_length)
{
    printf("\n%zu OE claims retrieved:\n\n", claims_length);
    size_t i = 0;
    for (; i < 3; i++)
    {
        printf("claims[%zu]: %s\n%u\n\n", i, claims[i].name, *claims[i].value);
    }
    for (; i < 16; i++)
    {
        printf(
            "claims[%zu]: %s (%zu)\n0x",
            i,
            claims[i].name,
            claims[i].value_size);
        for (size_t j = 0; j < claims[i].value_size; j++)
            printf("%02x", claims[i].value[j]);
        printf("\n\n");
    }
    // validity
    for (; i < 18; i++)
    {
        printf("claims[%zu]: %s\n", i, claims[i].name);
        uint32_t* date = (uint32_t*)claims[i].value;
        for (size_t j = 0; j < 6; j++)
            printf("%d ", date[j]);
        printf("\n\n");
    }
    // sgx endorsements
    for (; i < claims_length; i++)
    {
        printf("claims[%zu]: %s\n%s\n\n", i, claims[i].name, claims[i].value);
    }
}

// DCAP client (libdcap_quoteprov) log callback to this function.
void oecert_quote_provider_log(sgx_ql_log_level_t level, const char* message)
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
        set_log_fcn(oecert_quote_provider_log);
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

oe_result_t dump_oe_evidence(const uint8_t* evidence, size_t evidence_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_attestation_header_t* header = (oe_attestation_header_t*)evidence;
    OE_UNUSED(evidence_size);

    printf("\nOE Evidence:\n");
    printf("oe_attestation_header {\n");
    printf("    version: %d\n", header->version);
    printf("    format_id (hex): ");
    oe_hex_dump(header->format_id.b, OE_COUNTOF(header->format_id.b));
    printf("    data_size: %zu\n", header->data_size);

    OE_CHECK_MSG(
        dump_sgx_quote(header->data, evidence, evidence_size),
        "Failed to dump OE evidence. Error: (%s)\n",
        oe_result_str(result));

    printf("} oe_attestation_header\n");

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

oe_result_t get_oe_report_from_certificate(
    const uint8_t* certificate_in_der,
    size_t certificate_in_der_length,
    uint8_t** report,
    size_t* report_size)
{
    oe_result_t result = OE_UNEXPECTED;
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
        X509_OID_FOR_NEW_QUOTE_STRING,
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
        printf("Generate OE report, report_size = %zu\n", report_size);
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

        OE_CHECK_MSG(
            oe_verify_report(
                nullptr, remote_report, report_size, &parsed_report),
            "Failed to verify report. Error: (%s)\n",
            oe_result_str(result));

        log("========== OE report verified\n\n");
    }
    printf("generate_oe_report succeeded, more info in log file.\n");

    result = OE_OK;

done:
    if (remote_report)
        oe_free_report(remote_report);

    return result;
}

oe_result_t generate_oe_evidence(
    oe_enclave_t* enclave,
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

    oe_attestation_header_t* evidence_header = nullptr;
    oe_report_header_t* report_header = nullptr;
    sgx_quote_t* quote = nullptr;

    log("========== Getting OE evidence\n");

    // only retrieve endorsements when need to output endorsements file or
    // verify envidence
    if (endorsements_filename || verify)
    {
        get_plugin_evidence(
            enclave,
            &result,
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

    evidence_header = (oe_attestation_header_t*)evidence;
    report_header = (oe_report_header_t*)evidence_header->data;
    quote = (sgx_quote_t*)report_header->report;

    // Dump evidence
    if (verbose)
    {
        OE_CHECK_MSG(
            dump_oe_evidence(evidence, evidence_size),
            "Failed to dump OE evidence. Error: (%s)\n",
            oe_result_str(result));
    }
    else
    {
        // Print basic info to console
        printf("Generate OE evidence, evidence_size = %zu\n", evidence_size);
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
            dump_oe_endorsements(
                ((oe_attestation_header_t*)endorsements)->data,
                ((oe_attestation_header_t*)endorsements)->data_size),
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

        OE_CHECK(oe_verifier_initialize());

        OE_CHECK_MSG(
            oe_verify_evidence(
                NULL,
                evidence,
                evidence_size,
                endorsements,
                endorsements_size,
                NULL,
                0,
                &claims,
                &claims_length),
            "Failed to verify evidence. result=%u (%s)\n",
            result,
            oe_result_str(result));

        log("========== OE evidence verified.\n\n");

        if (verbose)
            dump_claims(claims, claims_length);

        OE_CHECK(oe_free_claims(claims, claims_length));
        OE_CHECK(oe_verifier_shutdown());
    }
    printf("generate_oe_evidence succeeded, more info in log file.\n");

    result = OE_OK;

done:
    return result;
}
