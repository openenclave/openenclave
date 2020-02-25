#include "tls_client.h"

int main()
{
    int retval;
    tls_client_t* client = NULL;
    tls_error_t error;

    retval = tls_client_connect("127.0.0.1", "12345", &client, &error);

    if (retval != 0)
        tls_dump_error(&error);

    return 0;
}
