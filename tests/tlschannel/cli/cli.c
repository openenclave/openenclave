// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <unistd.h>
#include "tlscli.h"

static void _err(const tlscli_err_t* err)
{
    tlscli_put_err(err);
    exit(1);
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
             true, "127.0.0.1", "12345", argv[1], argv[2], &cli, &err)) != 0)
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
