// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tlssrv.h"

int main()
{
    int r;
    tlssrv_t* server = NULL;
    tlssrv_err_t err;
    const char* ip = "127.0.0.1";
    const char* port = "12345";

    if ((r = tlssrv_startup(&err)) != 0)
    {
        tlssrv_put_err(&err);
        exit(1);
    }

    if ((r = tlssrv_create(ip, port, &server, &err)) != 0)
    {
        tlssrv_put_err(&err);
        exit(1);
    }

    if ((r = tlssrv_listen(server, &err)) != 0)
    {
        tlssrv_put_err(&err);
        exit(1);
    }

    if ((r = tlssrv_destroy(server, &err)) != 0)
    {
        tlssrv_put_err(&err);
        exit(1);
    }

    if ((r = tlssrv_shutdown(&err)) != 0)
    {
        tlssrv_put_err(&err);
        exit(1);
    }

    return 0;
}
