// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <libgen.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "oegencreds_u.h"

static int _write_file(
    const char* path,
    const void* data,
    size_t size,
    bool null_terminate)
{
    FILE* os;

    if (!(os = fopen(path, "w")))
        return -1;

    if (fwrite(data, 1, size, os) != size)
    {
        fclose(os);
        return -1;
    }

    if (null_terminate)
    {
        char c = '\0';
        if (fwrite(&c, 1, 1, os) != 1)
            return -1;
    }

    fclose(os);

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave;
    int retval;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    char path[PATH_MAX];

    /* Disable logging. */
    setenv("OE_LOG_LEVEL", "NONE", 1);

    if (argc != 1)
    {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        return 1;
    }

    /* Deduce enclave path from host path */
    {
        char* clone;
        const char* root;

        if (!(clone = strdup(argv[0])))
        {
            fprintf(stderr, "%s: calloc() failed\n", argv[0]);
            exit(1);
        }

        if (!(root = dirname(clone)))
        {
            fprintf(stderr, "%s: dirname() failed\n", argv[0]);
            exit(1);
        }

        snprintf(path, sizeof(path), "%s/oegencreds_enclave", root);

        free(clone);
    }

    r = oe_create_oegencreds_enclave(path, type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: failed create enclave: %s\n", argv[0], argv[1]);
        exit(1);
    }

    /* Generate and write the credentials */
    {
        uint8_t* cert = NULL;
        size_t cert_size;
        uint8_t* private_key = NULL;
        size_t private_key_size;

        r = oegencreds_ecall(
            enclave,
            &retval,
            &cert,
            &cert_size,
            &private_key,
            &private_key_size);

        if (r != OE_OK || retval != 0)
        {
            fprintf(stderr, "%s: failed to generate certificate\n", argv[0]);
            exit(1);
        }

        {
            char path[] = "cert.der";

            if (_write_file(path, cert, cert_size, false) != 0)
            {
                fprintf(stderr, "%s: failed to write %s\n", argv[0], path);
                exit(1);
            }

            printf("created %s\n", path);
        }

        {
            char path[] = "private_key.pem";

            if (_write_file(path, private_key, private_key_size, false) != 0)
            {
                fprintf(stderr, "%s: failed to write %s\n", argv[0], path);
                exit(1);
            }

            printf("created %s\n", path);
        }
    }

    r = oe_terminate_enclave(enclave);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: failed to terminate enclave\n", argv[0]);
        exit(1);
    }

    return 0;
}
