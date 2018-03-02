#include <mbedtls/sha256.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include "../args.h"

OE_ECALL void Hash(void* args_)
{
    Args* args = (Args*)args_;

    if (!args || !args->data)
        return;

    memset(args->hash, 0, sizeof(args->hash));
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, args->data, args->size);
    mbedtls_sha256_finish(&ctx, args->hash);
}
