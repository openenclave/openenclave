// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/host.h>

#include <openenclave/internal/tests.h>

#include <stdlib.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "intel_qve_thread_test_u.h"

#include "../../../host/hostthread.h"
typedef oe_mutex oe_mutex_t;
#define OE_MUTEX_INITIALIZER OE_H_MUTEX_INITIALIZER
static oe_mutex_t mutex = OE_MUTEX_INITIALIZER;

#define SKIP_RETURN_CODE 2

static const oe_uuid_t _sgx_quote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _tdx_quote_uuid = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};
typedef struct _input_params
{
    const char* enclave_filename;
    const char* evidence_filename;
    const oe_uuid_t* evidence_format;
    int thread_count;
    int duration;
} input_params_t;

static input_params_t _params;

// For reading quote file content

size_t get_filesize(FILE* fp)
{
    size_t size = 0;
    fseek(fp, 0, SEEK_END);
    size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    return size;
}

bool read_binary_file(
    const char* filename,
    uint8_t** data_ptr,
    size_t* size_ptr)
{
    size_t size = 0;
    uint8_t* data = NULL;
    size_t bytes_read = 0;
    bool result = false;
    FILE* fp = NULL;
#ifdef _WIN32
    if (fopen_s(&fp, filename, "rb") != 0)
#else
    if (!(fp = fopen(filename, "rb")))
#endif
    {
        fprintf(stderr, "Failed to open: %s\n", filename);
        goto exit;
    }

    *data_ptr = NULL;
    *size_ptr = 0;

    // Find file size
    size = get_filesize(fp);
    if (size == 0)
    {
        fprintf(stderr, "Empty file: %s\n", filename);
        goto exit;
    }

    data = (uint8_t*)malloc(size);
    if (data == NULL)
    {
        fprintf(
            stderr,
            "Failed to allocate memory of size %lu\n",
            (unsigned long)size);
        goto exit;
    }

    bytes_read = fread(data, sizeof(uint8_t), size, fp);
    if (bytes_read != size)
    {
        fprintf(stderr, "Failed to read file: %s\n", filename);
        goto exit;
    }

    result = true;

exit:
    if (fp)
    {
        fclose(fp);
    }

    if (!result)
    {
        if (data != NULL)
        {
            free(data);
            data = NULL;
        }
        bytes_read = 0;
    }

    *data_ptr = data;
    *size_ptr = bytes_read;

    return result;
}

static int _parse_args(int argc, const char* argv[])
{
    // parse 5 required arguments
    if (argc != 6)
    {
        printf(
            "Usage: %s <enclave file> <evidence file> <evidence format> "
            "<number of enclave thread> <duration (sec)>\n",
            argv[0]);
        return -1;
    }

    // parse 1 argument, the enclave file
    const char* enclave_file = argv[1];
    if (strlen(enclave_file) == 0)
    {
        printf("Invalid enclave file: %s\n", enclave_file);
        return -1;
    }
    _params.enclave_filename = enclave_file;

    // parse 2 argument, the evidence file
    const char* evidence_path = argv[2];
    if (strlen(evidence_path) == 0)
    {
        printf("Invalid tdx evidence path: %s\n", evidence_path);
        return -1;
    }
    _params.evidence_filename = evidence_path;

    // parse 3 argument, the format of evidence
    const char* evidence_format = argv[3];
    if (strncmp(evidence_format, "sgx", 3) == 0)
    {
        _params.evidence_format = &_sgx_quote_uuid;
    }
    else if (strncmp(evidence_format, "tdx", 3) == 0)
    {
        _params.evidence_format = &_tdx_quote_uuid;
    }
    else
    {
        printf("Invalid evidence format: %s\n", evidence_format);
        return -1;
    }

    // parse 4 argument, the number of threads
    int num_thread = atoi(argv[4]);
    if (num_thread <= 0)
    {
        printf("Invalid number of thread: %d\n", num_thread);
        return -1;
    }
    _params.thread_count = num_thread;

    // parse 5 argument, the number of threads
    int duration = atoi(argv[5]);
    if (duration <= 0)
    {
        printf("Invalid duration: %d\n", duration);
        return -1;
    }
    _params.duration = duration;

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result_oe = OE_UNEXPECTED;
    int ret_code = 0;

    oe_enclave_t* enclave = nullptr;
    uint8_t* tdx_evidence = nullptr;
    size_t tdx_evidence_size = 0;

    // number of request made in enclave
    int count_global = 0;

    if (_parse_args(argc, argv) != 0)
    {
        printf("Parse arguments failed\n");
        ret_code = 1;
        goto done;
    }

    if ((oe_get_create_flags() & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode (%s)\n", argv[0]);
        ret_code = SKIP_RETURN_CODE;
        goto done;
    }

    // Read tdx evidence file
    if (!read_binary_file(
            _params.evidence_filename, &tdx_evidence, &tdx_evidence_size))
    {
        printf("Failed to read tdx evidence file\n");
        ret_code = 1;
        goto done;
    }

    if ((result_oe = oe_create_intel_qve_thread_test_enclave(
             _params.enclave_filename,
             OE_ENCLAVE_TYPE_AUTO,
             OE_ENCLAVE_FLAG_DEBUG,
             nullptr,
             0,
             &enclave)) != OE_OK)
    {
        printf(
            "Failed to create enclave. result=%u (%s)\n",
            result_oe,
            oe_result_str(result_oe));
        ret_code = 1;
        goto done;
    }

    // Init Enclave TDX verifier
    init_tdx_verifier(enclave, &result_oe);
    if (result_oe != OE_OK)
    {
        printf(
            "Failed to create enclave. result=%u (%s)\n",
            result_oe,
            oe_result_str(result_oe));
        ret_code = 1;
        goto done;
    }

    {
        // Generate threads
        std::vector<std::thread> threads((size_t)_params.thread_count);
        for (size_t i = 0; i < threads.size(); i++)
        {
            printf("Creating thread %zu\n", i);
            threads[i] = std::thread([i,
                                      enclave,
                                      tdx_evidence,
                                      tdx_evidence_size,
                                      &count_global,
                                      &result_oe]() {
                oe_result_t result = OE_UNEXPECTED;
                int count = 0;
                run_enclave_thread(
                    enclave,
                    &result,
                    _params.evidence_format,
                    tdx_evidence,
                    tdx_evidence_size,
                    (double)_params.duration,
                    &count);

                if (result != OE_OK)
                {
                    printf(
                        "Thread %zu failed to run_enclave_thread, "
                        "result=%u (%s)\n",
                        i,
                        result,
                        oe_result_str(result));
                    result_oe = result;
                }
                else
                {
                    printf(
                        "Thread %zu finished, OPS %.1f (%d in %d sec)\n",
                        i,
                        (count / (double)_params.duration),
                        count,
                        _params.duration);
                }

                // aggregate result
                if (oe_mutex_lock(&mutex) == OE_OK)
                {
                    count_global += count;
                    oe_mutex_unlock(&mutex);
                }
            });
        }

        for (size_t i = 0; i < threads.size(); ++i)
        {
            threads[i].join();
        }

        printf(
            "Overall OPS %.1f (%d in %d sec)\n",
            (count_global / (double)_params.duration),
            count_global,
            _params.duration);
    }

done:
    if (enclave)
    {
        // Shutdown Enclave TDX verifier
        {
            oe_result_t result_oe = OE_UNEXPECTED;
            shutdown_tdx_verifier(enclave, &result_oe);
            if (result_oe != OE_OK)
            {
                printf(
                    "Failed to shutdown_tdx_verifier. result=%u (%s)\n",
                    result_oe,
                    oe_result_str(result_oe));
                ret_code = 1;
            }
        }

        oe_terminate_enclave(enclave);
    }

    if (tdx_evidence)
    {
        free(tdx_evidence);
    }

    // Skip if ret_code is 2
    if (result_oe != OE_OK && ret_code == 0)
    {
        ret_code = 1;
    }

    return ret_code;
}
