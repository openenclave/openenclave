// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/types.h>
#include "pingpong_u.h"

static bool got_pong = false;

void Log(const char* str, uint64_t x)
{
    printf("LOG: %s: %llu\n", str, OE_LLU(x));
}

void Pong(const char* in, char* out, int out_length)
{
    // printf("Pong: %s %s\n", in, out);

    if (in && out)
    {
        if (strcmp(in, "String1") == 0 && strcmp(out, "String2") == 0)
        {
            got_pong = true;
        }
        strcpy_s(out, out_length, in);
    }
}

static char buf[128];

OE_EXPORT int main_shared(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_pingpong_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %s\n", argv[0], argv[1]);
        return 1;
    }

    strcpy_s(buf, sizeof(buf), "String2");
    result = Ping(enclave, "String1", buf, sizeof(buf));
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: Ping Failed\n", argv[0]);
        return 1;
    }

    oe_terminate_enclave(enclave);

    if (!got_pong)
        fprintf(stderr, "%s: never received pong request\n", argv[0]);

    fprintf(stdout, "=== passed all tests (pingpong)\n");

    return 0;
}
