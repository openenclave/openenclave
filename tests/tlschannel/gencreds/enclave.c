// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "oegencreds.h"
#include "oegencreds_t.h"

void* _clone(const void* p, size_t n)
{
    void* clone;

    if (!(clone = oe_host_calloc(1, n)))
        return NULL;

    memcpy(clone, p, n);

    return clone;
}

int oegencreds_ecall(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    int ret = -1;
    uint8_t* cert = NULL;
    size_t cert_size;
    uint8_t* private_key = NULL;
    size_t private_key_size;

    *cert_out = NULL;
    *cert_size_out = 0;
    *private_key_out = NULL;
    *private_key_size_out = 0;

    if (oe_generated_attested_credentials(
            "CN=Open Enclave SDK,O=OESDK TLS,C=US",
            &cert,
            &cert_size,
            &private_key,
            &private_key_size) != 0)
    {
        fprintf(stderr, "oegencreds() failed\n");
        goto done;
    }

    if (!(*cert_out = _clone(cert, cert_size)))
    {
        fprintf(stderr, "out of memory\n");
        goto done;
    }

    if (!(*private_key_out = _clone(private_key, private_key_size)))
    {
        fprintf(stderr, "out of memory\n");
        goto done;
    }

    *cert_size_out = cert_size;
    *private_key_size_out = private_key_size;

    ret = 0;

done:

    if (cert)
        oe_free_key(cert, cert_size, NULL, 0);

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
