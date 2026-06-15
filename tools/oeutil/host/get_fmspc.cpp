// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "get_fmspc.h"
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parse_args_helper.h"

#define INPUT_PARAM_OPTION_INPUT_FILE "--input"
#define INPUT_PARAM_OPTION_HELP "--help"
#define SHORT_INPUT_PARAM_OPTION_INPUT_FILE "-i"
#define SHORT_INPUT_PARAM_OPTION_HELP "-h"

typedef struct _get_fmspc_parameters
{
    const char* input_filename;
} get_fmspc_parameters_t;

static get_fmspc_parameters_t _parameters;

static void _display_help(const char* command)
{
    printf("Get-fmspc Usage: %s get-fmspc <options>\n", command);
    printf("options:\n");
    printf(
        "\t%s, %s <filename>: input TDX evidence file.\n",
        SHORT_INPUT_PARAM_OPTION_INPUT_FILE,
        INPUT_PARAM_OPTION_INPUT_FILE);
    printf(
        "\t%s, %s: show this help message.\n",
        SHORT_INPUT_PARAM_OPTION_HELP,
        INPUT_PARAM_OPTION_HELP);
    printf("Example:\n");
    printf("\toeutil get-fmspc --input evidence.bin\n");
}

static int _parse_args(int argc, const char* argv[])
{
    // Clear parameters memory
    memset(&_parameters, 0, sizeof(_parameters));

    _parameters.input_filename = nullptr;

    int i = 2; // Start from the third argument (after command name)

    if (argc == 3 && (strcasecmp(INPUT_PARAM_OPTION_HELP, argv[i]) == 0 ||
                      strcasecmp(SHORT_INPUT_PARAM_OPTION_HELP, argv[i]) == 0))
    {
        _display_help(argv[0]);
        return 2; // Special return value for help
    }

    if (argc < 4)
    {
        _display_help(argv[0]);
        return 1;
    }

    while (i < argc)
    {
        if (strcasecmp(INPUT_PARAM_OPTION_INPUT_FILE, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_INPUT_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _parameters.input_filename = argv[i + 1];
            i += 2;
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

    if (!_parameters.input_filename)
    {
        printf("Input file is required.\n\n");
        _display_help(argv[0]);
        return 1;
    }

    return 0;
}

static int _read_evidence_file(
    const char* filename,
    uint8_t** data,
    uint32_t* size)
{
    FILE* fp = nullptr;
    long file_size = 0;
    uint8_t* buffer = nullptr;
    size_t bytes_read = 0;

#ifdef _WIN32
    if (fopen_s(&fp, filename, "rb") != 0 || fp == nullptr)
#else
    fp = fopen(filename, "rb");
    if (fp == nullptr)
#endif
    {
        printf("Failed to open input file: %s\n", filename);
        return 1;
    }

    // Get file size
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        printf("Failed to seek to end of file: %s\n", filename);
        fclose(fp);
        return 1;
    }

    file_size = ftell(fp);
    if (file_size <= 0)
    {
        printf("Invalid file size for: %s\n", filename);
        fclose(fp);
        return 1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        printf("Failed to seek to beginning of file: %s\n", filename);
        fclose(fp);
        return 1;
    }

    // Allocate buffer
    buffer = (uint8_t*)malloc((size_t)file_size);
    if (buffer == nullptr)
    {
        printf("Failed to allocate memory for file: %s\n", filename);
        fclose(fp);
        return 1;
    }

    // Read file
    bytes_read = fread(buffer, 1, (size_t)file_size, fp);
    fclose(fp);

    if (bytes_read != (size_t)file_size)
    {
        printf("Failed to read complete file: %s\n", filename);
        free(buffer);
        return 1;
    }

    *data = buffer;
    *size = (uint32_t)file_size;
    return 0;
}

int oeutil_get_fmspc(int argc, const char* argv[])
{
    int ret = 0;
    uint8_t* evidence_data = nullptr;
    uint32_t evidence_size = 0;
    uint8_t fmspc[OE_TDX_FMSPC_SIZE] = {0};
    oe_result_t result = OE_OK;

    // Parse command line arguments first to handle help
    ret = _parse_args(argc, argv);
    if (ret == 2) // Help was displayed
        return 0;
    if (ret != 0)
        return ret;

    printf("Getting FMSPC for input TDX evidence file.\n\n");

    // Read evidence file
    ret = _read_evidence_file(
        _parameters.input_filename, &evidence_data, &evidence_size);
    if (ret != 0)
        goto done;

    printf(
        "Read evidence file: %s (%u bytes)\n",
        _parameters.input_filename,
        evidence_size);

    // Extract FMSPC from the TDX quote
    result = oe_get_tdx_fmspc_from_quote(
        evidence_data, evidence_size, fmspc, sizeof(fmspc));

    if (result != OE_OK)
    {
        printf(
            "Failed to get FMSPC from quote. Error: %u (%s)\n",
            result,
            oe_result_str(result));
        ret = 1;
        goto done;
    }

    printf("FMSPC: ");
    for (uint32_t i = 0; i < (uint32_t)sizeof(fmspc); i++)
        printf("%02x", fmspc[i]);
    printf("\n");

done:
    if (evidence_data)
        free(evidence_data);

    return ret;
}
