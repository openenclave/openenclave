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
    if (set_log_fcn != NULL)
    {
        set_log_fcn(oecertdump_quote_provider_log);
    }
#endif
}

oe_result_t gen_report(oe_enclave_t* enclave)
{
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = NULL;
    oe_report_header_t* header = NULL;
    sgx_quote_t* quote = NULL;
    uint64_t quote_size = 0;

    log("========== Getting report\n");

    oe_result_t result = oe_get_report(
        enclave,
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL, // opt_params must be null
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
            uint8_t* endorsements_data = NULL;
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
                NULL, remote_report, report_size, &parsed_report);
            if (result != OE_OK)
            {
                log("Failed to verify report. result=%u (%s)\n",
                    result,
                    oe_result_str(result));

                // Print TCB Info to console if verification failed
                printf(
                    "oe_verify_report failure (%s)\n", oe_result_str(result));
                printf("QEID: ");
                oe_hex_dump(quote->user_data, 16);
                printf("CPU_SVN: ");
                oe_hex_dump(quote->report_body.cpusvn, SGX_CPUSVN_SIZE);
                printf("PCE_SVN: %02x\n", quote->pce_svn);

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

#endif // OE_LINK_SGX_DCAP_QL
