#include <openenclave.h>
#include "file_t.h"

extern OE_StructTI Object_ti;

OE_EXTERNC int TestReadFile(
    const char *path,
    unsigned int *checksum)
{
    int rc = -1;
    FILE* is = OE_NULL;
    const oe_size_t bufSize = 32;
    unsigned char buf[bufSize];
    OE_Result r;

    if (!path || !checksum)
        goto done;

    if ((r = Fopen(&is, path, "rb")) != OE_OK)
        goto done;

    oe_size_t n;
    while ((r = Fread(&n, buf, bufSize, is)) == OE_OK && n > 0)
    {
        for (oe_size_t i = 0; i < n; i++)
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
