// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tlssrv.h"

static void _err(const tlssrv_err_t* err)
{
    tlssrv_put_err(err);
    exit(1);
}

int main()
{
    int r;
    tlssrv_t* srv = NULL;
    tlssrv_err_t err;
    const char* ip = "127.0.0.1";
    const char* port = "12345";
    mbedtls_net_context conn;

    if ((r = tlssrv_startup(&err)) != 0)
        _err(&err);

    if ((r = tlssrv_create(ip, port, &srv, &err)) != 0)
        _err(&err);

    /* Wait for connections */
    for (;;)
    {
        /* Accept the next client connection */
        if ((r = tlssrv_accept(srv, &conn, &err)) != 0)
            _err(&err);

        /* Handle this connection */
        for (;;)
        {
            char buf[1024];
            size_t nbytes;

            if ((r = tlssrv_read(srv, buf, sizeof(buf), &err)) <= 0)
            {
                if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                    break;

                _err(&err);
            }

            nbytes = (size_t)r;

            if ((r = tlssrv_write(srv, buf, nbytes, &err)) <= 0)
                _err(&err);
        }
    }

    if ((r = tlssrv_destroy(srv, &err)) != 0)
        _err(&err);

    if ((r = tlssrv_shutdown(&err)) != 0)
        _err(&err);

    return 0;
}
