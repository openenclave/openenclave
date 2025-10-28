// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oeutil_u.h"

#include "generate_evidence.h"
#include "get_endorsements.h"
#include "parse_args_helper.h"

FILE* log_file = nullptr;

#define COMMAND_GENERATE_EVIDENCE "generate-evidence"
#define COMMAND_GET_ENDORSEMENTS "get-endorsements"

typedef enum _oeutil_command
{
    OEUTIL_UNKNOWN = 0,
    /**
     * Generate evidence, a report, or a certificate.
     */
    OEUTIL_GENERATE_EVIDENCE = 1,
    /**
     * Get endorsements for TDX evidence.
     */
    OEUTIL_GET_ENDORSEMENTS = 2,

} oeutil_command_t;

static void _display_help(const char* command)
{
    printf("Usage:\t%s <command> <options>\n", command);
    printf("where command can be any prefix of:\n");
    printf(
        "\t1. %s: generate evidence, a report, or a certificate.\n",
        COMMAND_GENERATE_EVIDENCE);
    printf(
        "\t2. %s: get endorsements for input TDX evidence.\n",
        COMMAND_GET_ENDORSEMENTS);
    printf("Options:\n\tType oeutil <command> --help for more information\n");
}

static oeutil_command_t _get_oeutil_command(int argc, const char* argv[])
{
    oeutil_command_t command_type = OEUTIL_UNKNOWN;

    if (argc < 2)
    {
        printf("Invalid command.\n");
        return command_type;
    }

    if (strncasecmp(COMMAND_GENERATE_EVIDENCE, argv[1], strlen(argv[1])) == 0)
    {
        command_type = OEUTIL_GENERATE_EVIDENCE;
    }
    else if (
        strncasecmp(COMMAND_GET_ENDORSEMENTS, argv[1], strlen(argv[1])) == 0)
    {
        command_type = OEUTIL_GET_ENDORSEMENTS;
    }
    else
    {
        printf("Invalid option: %s\n\n", argv[1]);
    }

    return command_type;
}

int main(int argc, const char* argv[])
{
    int ret = 0;
    oeutil_command_t command_type = OEUTIL_UNKNOWN;

    command_type = _get_oeutil_command(argc, argv);

    switch (command_type)
    {
        case OEUTIL_GENERATE_EVIDENCE:
            ret = oeutil_generate_evidence(argc, argv);
            break;
        case OEUTIL_GET_ENDORSEMENTS:
            ret = oeutil_get_endorsements(argc, argv);
            break;
        default:
            _display_help(argv[0]);
            ret = 1;
            break;
    }

    return ret;
}
