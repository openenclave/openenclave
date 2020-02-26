#include <unistd.h>
#include "tls_client.h"

int main()
{
    int retval;
    tls_client_t* client = NULL;
    tls_error_t error;

    retval = tls_client_connect("127.0.0.1", "12345", &client, &error);

    if (retval != 0)
    {
        tls_dump_error(&error);
        exit(1);
    }

    const char message[] = "abcdefghijklmnopqrstuvwxyz";

    printf("CLIENT.WRITE\n");

    retval = tls_client_write(client, message, sizeof(message), &error);
    if (retval < 0)
    {
        tls_dump_error(&error);
        exit(1);
    }

    printf("client.wrote=%d\n", retval);

    char buf[1024];

    printf("CLIENT.READ\n");

    retval = tls_client_read(client, buf, sizeof(buf), &error);
    if (retval < 0)
    {
        tls_dump_error(&error);
        exit(1);
    }

    printf("CLIENT.DONE\n");
    return 0;
}
