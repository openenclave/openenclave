// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/syscall/iov.h>
#include <openenclave/internal/syscall/sys/uio.h>
#include <openenclave/internal/syscall/types.h>
#include <openenclave/internal/utils.h>

int oe_iov_pack(
    const struct oe_iovec* iov,
    int iovcnt,
    void** buf_out,
    size_t* buf_size_out)
{
    int ret = -1;
    struct oe_iovec* buf = NULL;
    size_t buf_size = 0;
    size_t data_size = 0;

    if (buf_out)
        *buf_out = NULL;

    if (buf_size_out)
        *buf_size_out = 0;

    /* Reject invalid parameters. */
    if (iovcnt < 0 || (iovcnt > 0 && !iov) || !buf_out || !buf_size_out)
        goto done;

    /* Handle zero-sized iovcnt up front. */
    if (iovcnt == 0)
    {
        if (iov)
        {
            if (!(buf = oe_calloc(1, sizeof(uint64_t))))
                goto done;

            buf_size = sizeof(uint64_t);
        }

        *buf_out = buf;
        *buf_size_out = buf_size;
        buf = NULL;
        ret = 0;
        goto done;
    }

    /* Calculate the total number of data bytes. */
    for (int i = 0; i < iovcnt; i++)
        data_size += iov[i].iov_len;

    /* Calculate the total size of the resulting buffer. */
    buf_size = (sizeof(struct oe_iovec) * (size_t)iovcnt) + data_size;

    /* Allocate the output buffer. */
    if (!(buf = oe_calloc(1, buf_size)))
        goto done;

    /* Initialize the array elements. */
    {
        uint8_t* p = (uint8_t*)&buf[iovcnt];
        size_t n = data_size;
        int i;

        for (i = 0; i < iovcnt; i++)
        {
            const size_t iov_len = iov[i].iov_len;
            const void* iov_base = iov[i].iov_base;

            if (iov_len)
            {
                buf[i].iov_len = iov_len;
                buf[i].iov_base = (void*)(p - (uint8_t*)buf);

                if (!iov_base)
                    goto done;

                if (oe_memcpy_s(p, n, iov_base, iov_len) != OE_OK)
                    goto done;

                p += iov_len;
                n -= iov_len;
            }
        }

        /* Fail if the data was not exhausted. */
        if (n != 0)
            goto done;
    }

    *buf_out = buf;
    *buf_size_out = buf_size;
    buf = NULL;
    ret = 0;

done:

    if (buf)
        oe_free(buf);

    return ret;
}

int oe_iov_sync(
    const struct oe_iovec* iov,
    int iovcnt,
    const void* buf_,
    size_t buf_size)
{
    struct oe_iovec* buf = (struct oe_iovec*)buf_;
    int ret = -1;
    int i;
    size_t n;

    /* Reject invalid parameters. */
    if (iovcnt < 0 || (iovcnt > 0 && !iov))
        goto done;

    /* Synchronize the data. */
    for (i = 0, n = buf_size; i < iovcnt; i++)
    {
        if (buf[i].iov_len != iov[i].iov_len)
            goto done;

        if (buf[i].iov_len)
        {
            if (buf[i].iov_base && !iov[i].iov_base)
                goto done;

            if (!buf[i].iov_base && iov[i].iov_base)
                goto done;

            if (!buf[i].iov_base)
                continue;

            /* Fail if buffer data is exhausted. */
            if (n < buf[i].iov_len)
                goto done;

            /* Sync the base data for this element. */
            {
                /* Note: buf[i].iov_base is an offset here (not a pointer). */
                uint8_t* src = (uint8_t*)buf[i].iov_base + (uint64_t)buf;
                size_t src_size = buf[i].iov_len;
                uint8_t* dest = (uint8_t*)iov[i].iov_base;
                size_t dest_size = iov[i].iov_len;

                if (src_size != dest_size)
                    goto done;

                if (src < (uint8_t*)buf || src > (uint8_t*)buf + buf_size)
                    goto done;

                if (oe_memcpy_s(dest, dest_size, src, src_size) != OE_OK)
                    goto done;
            }
        }

        n -= buf[i].iov_len;
    }

    ret = 0;

done:

    return ret;
}
