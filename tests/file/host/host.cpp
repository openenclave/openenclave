// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/types.h>
#include <wchar.h>
#include "file_u.h"

#if 1
#define D(X)
#else
#define D(X) X
#endif

void Log(const char* s, uint64_t x)
{
    printf("Log(%s, %llu)\n", s, OE_LLU(x));
}

MY_FILE* Fopen(const char* filename, const char* modes)
{
    D(printf("Fopen(filename=%s, modes=%s)\n", filename, modes);)
    FILE* is;
#ifdef _WIN32
    fopen_s(&is, filename, modes);
#else
    is = fopen(filename, modes);
#endif
    D(printf("Fopen(): return=%p\n", is);)
    return (MY_FILE*)is;
}

size_t Fread(void* ptr, size_t size, MY_FILE* stream)
{
    D(printf("Fread(ptr=%p, size=%zu, stream=%p)\n", ptr, size, stream);)
    size_t n = fread(ptr, 1, size, (FILE*)stream);
    D(printf("Fread(): return=%zu\n", n);)
    return n;
}

int Fclose(MY_FILE* stream)
{
    D(printf("Fclose(stream=%p)\n", stream);)
    int r = fclose((FILE*)stream);
    D(printf("Fclose(): return=%d\n", r);)
    return r;
}

static int _get_file_check_sum(const char* path, unsigned int* checksum)
{
    int rc = -1;
    FILE* is = NULL;

    if (checksum)
        *checksum = 0;

    /* Reject null parameters */
    if (!path || !checksum)
        goto done;

        /* Open the input file */
#ifdef _WIN32
    if (fopen_s(&is, path, "rb") != 0)
#else
    if (!(is = fopen(path, "rb")))
#endif
        goto done;

    size_t n;
    unsigned char buf[32];
    while ((n = fread(buf, 1, sizeof(buf), is)) > 0)
    {
        for (size_t i = 0; i < n; i++)
            (*checksum) += buf[i];
    }

    rc = 0;

done:

    if (is)
        fclose(is);

    return rc;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_file_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %u\n", argv[0], result);
        return 1;
    }

    {
        unsigned int checksum1;
        if (_get_file_check_sum(argv[1], &checksum1) != 0)
        {
            fprintf(stderr, "%s: _get_file_check_sum() failed", argv[0]);
            return 1;
        }

#if 0
        printf("checksum=%u\n", checksum1);
#endif

        unsigned int checksum2 = 0;
        int ret = 0;
        if (TestReadFile(enclave, &ret, argv[1], &checksum2) != OE_OK)
        {
            fprintf(stderr, "%s: TestReadFile() failed: %d\n", argv[0], ret);
            return 1;
        }

        if (checksum1 != checksum2)
        {
            fprintf(
                stderr,
                "%s: checksum mismatch: checksum1=%x, checksum2=%#x\n",
                argv[0],
                checksum1,
                checksum2);
            return 1;
        }

#if 0
        printf("checksum=%u\n", checksum1);
#endif
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (file)\n");

    return 0;
}
