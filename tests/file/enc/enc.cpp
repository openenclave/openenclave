// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "file_t.h"

OE_EXTERNC int TestReadFile(const char* path, unsigned int* checksum)
{
    int rc = -1;
    MY_FILE* is = NULL;
    const size_t buf_size = 32;
    unsigned char buf[buf_size];
    oe_result_t r;

    if (!path || !checksum)
        goto done;

    if ((r = Fopen(&is, path, "rb")) != OE_OK)
        goto done;

    size_t n;
    while ((r = Fread(&n, buf, buf_size, is)) == OE_OK && n > 0)
    {
        for (size_t i = 0; i < n; i++)
            (*checksum) += buf[i];
    }

    if (r != OE_OK)
        goto done;

    rc = 0;

done:

    if (is)
    {
        int ret;
        if ((r = Fclose(&ret, is)) != OE_OK)
            rc = -1;
    }

    return rc;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    256,  /* NumStackPages */
    4);   /* NumTCS */
