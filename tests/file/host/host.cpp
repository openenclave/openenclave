#include <limits.h>
#include <wchar.h>
#include <openenclave/host.h>
#include "file_u.h"

#if 1
# define D(X)
#else
# define D(X) X
#endif

void Log(const char* s, uint64_t x)
{
    printf("Log(%s, %lu)\n", s, x);
}

FILE *Fopen(
    const char *filename,
    const char *modes)
{
    D( printf("Fopen(filename=%s, modes=%s)\n", filename, modes); )
    FILE* is = fopen(filename, modes);
    D( printf("Fopen(): return=%p\n", is); )
    return is;
}

size_t Fread(
    void *ptr,
    size_t size,
    FILE *stream)
{
    D( printf("Fread(ptr=%p, size=%zu, stream=%p)\n", ptr, size, stream); )
    size_t n = fread(ptr, 1, size, stream);
    D( printf("Fread(): return=%zu\n", n); )
    return n;
}

int Fclose(
    FILE *stream)
{
    D( printf("Fclose(stream=%p)\n", stream); )
    int r = fclose(stream);
    D( printf("Fclose(): return=%d\n", r); )
    return r;
}

static int _GetFileCheckSum(
    const char *path,
    unsigned int *checksum)
{
    int rc = -1;
    FILE* is = NULL;

    if (checksum)
        *checksum = 0;

    /* Reject null parameters */
    if (!path || !checksum)
        goto done;

    /* Open the input file */
    if (!(is = fopen(path, "rb")))
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
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = OE_CreateEnclave(argv[1], CREATE_FLAGS, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %u\n", argv[0], result);
        return 1;
    }

    {
        unsigned int checksum1;
        if (_GetFileCheckSum(argv[1], &checksum1) != 0)
        {
            fprintf(stderr, "%s: _GetFileCheckSum() failed", argv[0]);
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
            fprintf(stderr, "%s: checksum mismatch\n", argv[0]);
            return 1;
        }

#if 0
        printf("checksum=%u\n", checksum1);
#endif
    }

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (file)\n");

    return 0;
}
