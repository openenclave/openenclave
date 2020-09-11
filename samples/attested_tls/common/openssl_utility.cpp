// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openssl_utility.h"
#include <stdio.h>
#include <string.h>

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int ret = -1;
    unsigned char buf[200];
    int bytes_read = 0;
    do
    {
        int len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(ssl_session, buf, (size_t)len);
        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            printf("Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }
        printf(" %d bytes read from session peer\n", bytes_read);
#ifdef ADD_TEST_CHECKING
        // check to to see if received payload is expected
        if ((bytes_read != payload_length) ||
            (memcmp(payload, buf, bytes_read) != 0))
        {
            printf(
                "ERROR: expected reading %lu bytes but only "
                "received %d bytes\n",
                payload_length,
                bytes_read);
            ret = bytes_read;
            goto exit;
        }
        else
        {
            printf(" received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }
        printf("Verified: the contents of peer payload were expected\n\n");
#endif
    } while (1);

exit:
    return ret;
}

int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int bytes_written = 0;
    int ret = 0;

    while ((bytes_written = SSL_write(ssl_session, payload, payload_length)) <=
           0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf("Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }

    printf("%lu bytes written to session peer \n\n", payload_length);
exit:
    return ret;
}