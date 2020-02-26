#include "common.h"
#include <mbedtls/error.h>
#include <stdio.h>
#include <string.h>

void tls_clear_error(tls_error_t* error)
{
    if (error)
    {
        error->code = 0;
        error->message[0] = '\0';
        error->detail[0] = '\0';
    }
}

void tls_set_mbedtls_error(tls_error_t* error, int code, const char* detail)
{
    tls_clear_error(error);

    if (error && code)
    {
        error->code = code;

        if (detail)
        {
            memcpy(error->detail, detail, sizeof(error->detail));
            error->detail[sizeof(error->detail) - 1] = '\0';
        }

        mbedtls_strerror(code, error->message, sizeof(error->message));
    }
}

void tls_set_error(tls_error_t* error, const char* message, const char* detail)
{
    tls_clear_error(error);

    if (error)
    {
        error->code = -1;

        if (message)
        {
            memcpy(error->message, message, sizeof(error->message));
            error->message[sizeof(error->message) - 1] = '\0';
        }

        if (detail)
        {
            memcpy(error->detail, detail, sizeof(error->detail));
            error->detail[sizeof(error->detail) - 1] = '\0';
        }
    }
}

void tls_dump_error(const tls_error_t* error)
{
    printf("error: %d: %s: %s\n", error->code, error->message, error->detail);
}
