// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <string.h>

#include <openssl/ssl.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

#define HYBRID_GROUP "X25519MLKEM768"

static char* cert = NULL;
static char* privkey = NULL;

static int test_tls13_hybrid_mlkem(void)
{
    SSL_CTX* client_ctx = NULL;
    SSL_CTX* server_ctx = NULL;
    SSL* client_ssl = NULL;
    SSL* server_ssl = NULL;
    int result = 0;

    if (!TEST_true(create_ssl_ctx_pair(
            NULL,
            TLS_server_method(),
            TLS_client_method(),
            TLS1_3_VERSION,
            TLS1_3_VERSION,
            &server_ctx,
            &client_ctx,
            cert,
            privkey)) ||
        !TEST_true(SSL_CTX_set1_groups_list(server_ctx, HYBRID_GROUP)) ||
        !TEST_true(SSL_CTX_set1_groups_list(client_ctx, HYBRID_GROUP)) ||
        !TEST_true(create_ssl_objects(
            server_ctx, client_ctx, &server_ssl, &client_ssl, NULL, NULL)) ||
        !TEST_true(
            create_ssl_connection(server_ssl, client_ssl, SSL_ERROR_NONE)) ||
        !TEST_int_eq(SSL_version(server_ssl), TLS1_3_VERSION) ||
        !TEST_int_eq(SSL_version(client_ssl), TLS1_3_VERSION) ||
        !TEST_str_eq(SSL_get0_group_name(server_ssl), HYBRID_GROUP) ||
        !TEST_str_eq(SSL_get0_group_name(client_ssl), HYBRID_GROUP))
        goto done;

    result = 1;

done:
    SSL_free(server_ssl);
    SSL_free(client_ssl);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    return result;
}

OPT_TEST_DECLARE_USAGE("certsdir\n")

int setup_tests(void)
{
    const char* certsdir = NULL;

    if (!test_skip_common_options() ||
        !TEST_ptr(certsdir = test_get_argument(0)) ||
        !TEST_ptr(cert = test_mk_file_path(certsdir, "servercert.pem")) ||
        !TEST_ptr(privkey = test_mk_file_path(certsdir, "serverkey.pem")))
        return 0;

    ADD_TEST(test_tls13_hybrid_mlkem);
    return 1;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
}