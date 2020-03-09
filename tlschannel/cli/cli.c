// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <string.h>
#include <unistd.h>
#include "tlscli.h"

static void _err(const tlscli_err_t* err)
{
    tlscli_put_err(err);
    exit(1);
}

#define MRENCLAVE_SIZE 32
#define MRSIGNER_SIZE 32
#define ISVPRODID_SIZE 16

static void _dump(const char* msg, const uint8_t* data, size_t size)
{
    printf("%s: ", msg);

    for (size_t i = 0; i < size; i++)
    {
        printf("%02x", data[i]);

        if (i + 1 != size)
            printf(" ");
    }

    printf("\n");
}

static int _verify_identity(
    void* arg,
    const uint8_t* mrenclave,
    size_t mrenclave_size,
    const uint8_t* mrsigner,
    size_t mrsigner_size,
    const uint8_t* isvprodid,
    size_t isvprodid_size,
    uint64_t isvsvn)
{
    const uint64_t ISVSVN = 3;
    const uint8_t ISVPRODID[ISVPRODID_SIZE] = {2};
    // clang-format off
    const uint8_t MRSIGNER[] =
    {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a,
        0xa2, 0x88, 0x90, 0xce, 0x73, 0xe4, 0x33, 0x63,
        0x83, 0x77, 0xf1, 0x79, 0xab, 0x44, 0x56, 0xb2,
        0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0x0a
    };
    // clang-format on

    (void)arg;

    if (!mrenclave || !mrsigner || !isvprodid)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return -1;
    }

    if (mrenclave_size != MRENCLAVE_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return -1;
    }

    if (mrsigner_size != MRSIGNER_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return -1;
    }

    if (isvprodid_size != ISVPRODID_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return -1;
    }

    printf("\n");
    printf("=== _verify_identity()\n");
    _dump("MRENCLAVE", mrenclave, mrenclave_size);
    _dump("MRSIGNER", mrsigner, mrsigner_size);
    _dump("ISVPRODID", isvprodid, isvprodid_size);
    printf("ISVSVN: %lu\n", isvsvn);
    printf("\n");

    if (memcmp(isvprodid, ISVPRODID, ISVPRODID_SIZE) != 0)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return -1;
    }

    if (memcmp(mrsigner, MRSIGNER, MRSIGNER_SIZE) != 0)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return -1;
    }

    if (isvsvn != ISVSVN)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return -1;
    }

    return 0;
}

int main(int argc, const char* argv[])
{
    int r;
    tlscli_t* cli = NULL;
    tlscli_err_t err;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s cert-der private-key-pem\n", argv[0]);
        exit(1);
    }

    if (access(argv[1], R_OK) != 0)
    {
        fprintf(stdout, "%s: cannot open %s\n", argv[0], argv[1]);
        exit(1);
    }

    if (access(argv[2], R_OK) != 0)
    {
        fprintf(stdout, "%s: cannot open %s\n", argv[0], argv[2]);
        exit(1);
    }

    if ((r = tlscli_startup(&err)) != 0)
        _err(&err);

    if ((r = tlscli_connect(
             true,
             "127.0.0.1",
             "12345",
             _verify_identity,
             NULL,
             argv[1],
             argv[2],
             &cli,
             &err)) != 0)
    {
        _err(&err);
    }

    const char message[] = "abcdefghijklmnopqrstuvwxyz";

    for (size_t i = 0; i < 10; i++)
    {
        if ((r = tlscli_write(cli, message, sizeof(message), &err)) < 0)
            _err(&err);

        char buf[1024];

        if ((r = tlscli_read(cli, buf, sizeof(buf), &err)) < 0)
            _err(&err);

        printf("buf{%s}\n", buf);
    }

    tlscli_destroy(cli, &err);

    tlscli_shutdown(&err);

    return 0;
}
