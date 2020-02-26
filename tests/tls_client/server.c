#include "tls_server.h"

int main()
{
    int retval;
    tls_server_t* server = NULL;
    tls_error_t error;
    const char* ip = "127.0.0.1";
    const char* port = "12345";

    if ((retval = tls_server_create(ip, port, &server, &error)) != 0)
    {
        tls_dump_error(&error);
        exit(1);
    }

    if ((retval = tls_server_listen(server, &error)) != 0)
    {
        tls_dump_error(&error);
        exit(1);
    }

    printf("SUCCESS!\n");

    return 0;
}
