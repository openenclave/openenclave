// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <getopt.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>

#include "oeseal_u.h"

#define COMMAND_NAME_SEAL "seal"
#define COMMAND_NAME_UNSEAL "unseal"

#define SKIP_RETURN_CODE 2

typedef enum _command_t
{
    COMMAND_UNSUPPORTED,
    COMMAND_SEAL,
    COMMAND_UNSEAL
} command_t;

static void _print_helper()
{
    printf("Usage: oeseal <command> [<args>]\n"
           "command: seal, unseal\n"
           "args:\n"
           "  -h, --help: Helper message\n"
           "  -e, --enclave: Enclave binary\n"
           "  -i, --input: Input file\n"
           "  -o, --output: Output file\n"
           "  -v, --verbose: Enable the verbose output\n");
}

static command_t _process_command(const char* command)
{
    command_t result = COMMAND_UNSUPPORTED;

    if (strcmp(command, COMMAND_NAME_SEAL) == 0)
        result = COMMAND_SEAL;
    else if (strcmp(command, COMMAND_NAME_UNSEAL) == 0)
        result = COMMAND_UNSEAL;

    return result;
}

static oe_result_t _create_enclave(const char* path, oe_enclave_t** enclave)
{
    return oe_create_oeseal_enclave(
        path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG_AUTO,
        NULL,
        0,
        enclave);
}

static oe_result_t _read_file(const char* path, uint8_t** data, size_t* size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* _data = NULL;
    long file_size = 0;
    size_t _size = 0;
    FILE* f = NULL;

    if (!path || !data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    f = fopen(path, "r");
    if (f == NULL)
        OE_RAISE_MSG(OE_FAILURE, "Unable to open %s", path);

    fseek(f, 0, SEEK_END);

    file_size = ftell(f);
    if (file_size == -1)
        OE_RAISE(OE_FAILURE);

    _size = (size_t)file_size;

    fseek(f, 0, SEEK_SET);

    _data = malloc(_size);
    if (_data == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (fread(_data, _size, 1, f) != 1)
        OE_RAISE(OE_FAILURE);

    *data = _data;
    *size = _size;

    result = OE_OK;

done:
    if (f)
        fclose(f);

    return result;
}

static oe_result_t _write_file(const char* path, uint8_t* data, size_t size)
{
    oe_result_t result = OE_FAILURE;
    FILE* f = NULL;

    if (!path || !data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    f = fopen(path, "w");
    if (f == NULL)
        OE_RAISE_MSG(OE_FAILURE, "Unable to open %s", path);

    if (fwrite(data, size, 1, f) != 1)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    if (f)
        fclose(f);

    return result;
}

int main(int argc, const char* argv[])
{
    command_t command = COMMAND_UNSUPPORTED;
    oe_result_t result = OE_FAILURE;
    oe_enclave_t* enclave = NULL;
    output_t output_data = {0};
    const char* output = NULL;
    uint8_t* data = NULL;
    bool verbose = false;
    size_t size = 0;
    int ret = 1;
    int c = 0;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        fprintf(stderr, "oeseal not supported in simulation mode.\n");
        ret = SKIP_RETURN_CODE;
        goto exit;
    }

    if (argc < 2)
    {
        _print_helper();
        goto exit;
    }

    command = _process_command(argv[1]);
    if (command == COMMAND_UNSUPPORTED)
    {
        fprintf(stderr, "Unknown command %s\n", argv[1]);
        _print_helper();
        goto exit;
    }

    while (1)
    {
        static struct option long_options[] = {
            {"help", no_argument, NULL, 'h'},
            {"enclave", required_argument, NULL, 'e'},
            {"input", required_argument, NULL, 'i'},
            {"output", required_argument, NULL, 'o'},
            {"verbose", no_argument, NULL, 'v'},
            {NULL, 0, NULL, 0},
        };
        static char short_options[] = "he:p:i:o:v";

        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
            break;

        switch (c)
        {
            case 'h':
                _print_helper();
                break;
            case 'e':
                result = _create_enclave(optarg, &enclave);
                if (result != OE_OK)
                {
                    fprintf(stderr, "Failed to create the enclave\n");
                    goto exit;
                }
                break;
            case 'i':
                result = _read_file(optarg, &data, &size);
                if (result != OE_OK)
                {
                    fprintf(stderr, "Failed to read the file\n");
                    goto exit;
                }
                break;
            case 'o':
                output = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                break;
        }
    }

    if (command == COMMAND_SEAL)
        enc_seal(enclave, &result, data, size, &output_data, verbose);
    else // COMMAND_UNSEAL
        enc_unseal(enclave, &result, data, size, &output_data, verbose);

    if (result != OE_OK)
        goto exit;

    printf(
        "oeseal %s succeeded.\n",
        (command == COMMAND_SEAL) ? COMMAND_NAME_SEAL : COMMAND_NAME_UNSEAL);

    if (output)
    {
        if (_write_file(output, output_data.data, output_data.size) != OE_OK)
        {
            fprintf(stderr, "Failed to write to the file\n");
            goto exit;
        }
        printf("File %s created.\n", output);
    }
    printf("\n");

    ret = 0;

exit:
    if (enclave)
        oe_terminate_enclave(enclave);

    free(data);
    free(output_data.data);

    return ret;
}
