// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/syscall.h>
#include <openenclave/internal/tests.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../../tests.h"
#include "crypto_t.h"

char* oe_host_strdup(const char* str)
{
    size_t n = oe_strlen(str);
    char* dup = (char*)oe_host_malloc(n + 1);

    if (dup)
    {
        memcpy(dup, str, n + 1);
    }

    return dup;
}

static oe_result_t _syscall_hook(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6,
    long* ret)
{
    oe_result_t result = OE_UNSUPPORTED;

#if !defined(__aarch64__)
    OE_UNUSED(arg4);
#endif
    OE_UNUSED(arg5);
    OE_UNUSED(arg6);

    if (ret)
    {
        *ret = -1;
    }

    if (!ret)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    switch (number)
    {
#if defined(__aarch64__)
        case SYS_openat:
        {
            /* MUSL ORs 'flags' with O_LARGEFILE when forwarding sys_open to
             * SYS_openat.
             */
            const int flags = (const int)arg3;
            if (((flags & O_ACCMODE) == O_RDONLY))
            {
                int rval = -1;
                OE_TEST(
                    OE_OK ==
                    f_openat(
                        &rval, (int)arg1, (char*)arg2, (int)arg3, (int)arg4));
                *ret = (long)rval;
                result = OE_OK;
            }
            break;
        }
#else
        case SYS_open:
        {
            const int flags = (const int)arg2;
            if (flags == O_RDONLY)
            {
                int rval = -1;
                OE_TEST(
                    OE_OK == f_open(&rval, (char*)arg1, (int)arg2, (int)arg3));
                *ret = (long)rval;
                result = OE_OK;
            }
            break;
        }
#endif
        case SYS_read:
        {
            int rval = -1;
            OE_TEST(
                OE_OK == f_read(&rval, (int)arg1, (char*)arg2, (size_t)arg3));
            *ret = (long)rval;
            result = OE_OK;
            break;
        }
        case SYS_readv:
        {
            /* Handle SYS_readv because fread invokes readv internally
             * To avoid dealing with linux-specific readv semantics on Windows,
             * marshal this as a synchronous C read() invocation.
             */

            struct iovec* iov = (struct iovec*)arg2;

            // determine the total buffer size
            size_t buf_size = sizeof(struct iovec) * (size_t)arg3;
            size_t data_size = 0;
            for (size_t i = 0; i < (size_t)arg3; ++i)
            {
                data_size += iov[i].iov_len;
            }
            buf_size += data_size;

            // create the local buffer
            struct iovec* iov_host = (struct iovec*)malloc(buf_size);
            char* data_pos =
                (char*)iov_host + sizeof(struct iovec) * (size_t)arg3;

            // initialize the buffers
            char* buf_pos = data_pos;
            for (size_t i = 0; i < (size_t)arg3; ++i)
            {
                iov_host[i].iov_base = buf_pos;
                iov_host[i].iov_len = iov[i].iov_len;
                buf_pos += iov[i].iov_len;
            }

            // make the host call
            int rval = -1;
            OE_TEST(OE_OK == f_read(&rval, (int)arg1, data_pos, data_size));
            *ret = (long)rval;

            if (rval > 0)
            {
                // copy the data returned from the host
                for (size_t i = 0; i < (size_t)arg3; ++i)
                {
                    memcpy(
                        iov[i].iov_base, iov_host[i].iov_base, iov[i].iov_len);
                }
            }

            // release the local buffer
            free(iov_host);

            result = OE_OK;
            break;
        }
        case SYS_close:
        {
            int rval = -1;
            OE_TEST(OE_OK == f_close(&rval, (int)arg1));
            *ret = (long)rval;
            result = OE_OK;
            break;
        }
        default:
        {
            /* Avoid OE_RAISE here to reduce error log volume since the
             * syscall handler allows falling back to defaults */
            OE_TRACE_VERBOSE("Unsupported _syscall_hook number:%#x\n", number);
            break;
        }
    }

done:
    return result;
}

void test()
{
    oe_register_syscall_hook(_syscall_hook);
    TestAll();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */

#define TA_UUID                                            \
    { /* f0be7db0-ce7c-4dc4-b8c8-b161f4216225 */           \
        0xf0be7db0, 0xce7c, 0x4dc4,                        \
        {                                                  \
            0xb8, 0xc8, 0xb1, 0x61, 0xf4, 0x21, 0x62, 0x25 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    2 * 1024 * 1024,
    24 * 1024,
    0,
    "1.0.0",
    "Crypto test")
