#ifndef _TLS_CHANNEL_COMMON_H
#define _TLS_CHANNEL_COMMON_H

#include <stdbool.h>

#define CERT_PATH "/tmp/oe_attested_cert.der"
#define PRIVATE_KEY_PATH "/tmp/oe_private_key.pem"

typedef struct _tls_error
{
    int code;
    char message[1024];
    char detail[1024];
} tls_error_t;

void tls_clear_error(tls_error_t* error);

void tls_set_mbedtls_error(tls_error_t* error, int code, const char* detail);

void tls_set_error(tls_error_t* error, const char* message, const char* detail);

void tls_dump_error(const tls_error_t* error);

#endif /* _TLS_CHANNEL_COMMON_H */
