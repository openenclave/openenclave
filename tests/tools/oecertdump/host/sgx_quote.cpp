// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgx_quote.h"

#include <openenclave/host.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oecertdump_u.h"

#if defined(__linux__)
#include <dlfcn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

#include "../../../../common/sgx/collateral.h"
#include "../../../../common/sgx/quote.h"
#include "../../../../host/sgx/sgxquoteprovider.h"

#ifdef OE_LINK_SGX_DCAP_QL

extern FILE* log_file;

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
    printf("        uuid: ");
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

    printf("    qe_auth_data {\n");
    printf("        size: %d\n", qe_auth_data.size);
    printf("        data (hex): ");
    oe_hex_dump(qe_auth_data.data, qe_auth_data.size);
    printf("    } qe_auth_data\n");

    printf("    qe_cert_data {\n");
    printf("        type: 0x%x\n", qe_cert_data.type);
    printf("        size: %d\n", qe_cert_data.size);
    printf("        qe cert:\n");
    printf("%s\n", qe_cert_data.data);
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

            log("========== Got endorsements, size = %zu\n",
                endorsements_data_size);
            oe_sgx_endorsements_t endorsements;
            result = oe_parse_sgx_endorsements(
                (oe_endorsements_t*)endorsements_data,
                endorsements_data_size,
                &endorsements);

            log("Revocation TCB_INFO:\n");
            oe_sgx_endorsement_item tcb_info =
                endorsements.items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO];
            log("%s\n\n", tcb_info.data);

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
