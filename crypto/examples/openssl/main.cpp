#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

int LoadFile(const string& path, vector<char>& v)
{
    ifstream is(path.c_str());

    if (!is)
        return -1;

    char c;

    while (is.get(c))
        v.push_back(c);

    return 0;
}

STACK_OF(X509) * LoadCertChain(const char* pem)
{
    static const char BEGIN_CERTIFICATE[] = "-----BEGIN CERTIFICATE-----";
    static const size_t BEGIN_CERTIFICATE_LEN = sizeof(BEGIN_CERTIFICATE) - 1;
    static const char END_CERTIFICATE[] = "-----END CERTIFICATE-----";
    static const size_t END_CERTIFICATE_LEN = sizeof(END_CERTIFICATE) - 1;
    STACK_OF(X509)* result = NULL;
    STACK_OF(X509)* sk = NULL;
    BIO* bio = NULL;
    X509* x509 = NULL;

    // Check parameters:
    if (!pem)
        goto done;

    // Create empty X509 stack:
    if (!(sk = sk_X509_new_null()))
        goto done;

    while (*pem)
    {
        const char* end;

        /* The PEM certificate must start with this */
        if (strncmp(pem, BEGIN_CERTIFICATE, BEGIN_CERTIFICATE_LEN) != 0)
            goto done;

        /* Find the end of this PEM certificate */
        {
            if (!(end = strstr(pem, END_CERTIFICATE)))
                goto done;

            end += END_CERTIFICATE_LEN;
        }

        /* Skip trailing spaces */
        while (isspace(*end))
            end++;

        /* Create a BIO for this certificate */
        if (!(bio = BIO_new_mem_buf(pem, end - pem)))
            goto done;

        /* Read BIO into X509 object */
        if (!(x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)))
            goto done;

        // Push certificate onto stack:
        {
            if (!sk_X509_push(sk, x509))
                goto done;

            x509 = NULL;
        }

        // Release the bio:
        BIO_free(bio);
        bio = NULL;

        pem = end;
    }

    result = sk;

done:

    if (bio)
        BIO_free(bio);

    if (!result && sk)
        sk_X509_pop_free(sk, X509_free);

    return result;
}

int main(int argc, const char* argv[])
{
    int ret = 1;
    BIO* certbio = NULL;
    BIO* outbio = NULL;
    X509* cert = NULL;
    X509* error_cert = NULL;
    X509_NAME* subject = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    vector<char> data;

    // Check arguments:
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s cert chain\n", argv[0]);
        goto done;
    }

    // Initialize OpenSSL:
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create stdout BIO:
    if (!(outbio = BIO_new_fp(stdout, BIO_NOCLOSE)))
        goto done;

    // Create context for verification:
    if (!(ctx = X509_STORE_CTX_new()))
    {
        fprintf(stderr, "%s: X509_STORE_CTX_new() failed\n", argv[0]);
        goto done;
    }

    // Load the certificate:
    if (!(certbio = BIO_new(BIO_s_file())) ||
        !BIO_read_filename(certbio, argv[1]) ||
        !(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
    {
        fprintf(stderr, "%s: failed to load certificate\n", argv[0]);
        exit(1);
    }

    // Load the certificate chain file:
    {
        if (LoadFile(argv[2], data) != 0)
        {
            fprintf(stderr, "%s: failed to load %s\n", argv[0], argv[2]);
            exit(1);
        }

        data.push_back('\0');
    }

    // Load the CA:
    if (!(chain = LoadCertChain(&data[0])))
    {
        fprintf(stderr, "%s: failed to load CA\n", argv[0]);
        exit(1);
    }

    // Initialize the verification context:
    if (!X509_STORE_CTX_init(ctx, NULL, NULL, NULL))
    {
        fprintf(stderr, "%s: X509_STORE_CTX_init() failed\n", argv[0]);
        exit(1);
    }

    X509_STORE_CTX_set_cert(ctx, cert);
    // X509_STORE_CTX_set_chain(ctx, chain);
    X509_STORE_CTX_trusted_stack(ctx, chain);

    // Verify the certificate:
    if (!X509_verify_cert(ctx))
    {
        fprintf(
            stderr,
            "%s: X509_verify_cert(): %s\n",
            argv[0],
            X509_verify_cert_error_string(ctx->error));

        error_cert = X509_STORE_CTX_get_current_cert(ctx);
        subject = X509_NAME_new();
        subject = X509_get_subject_name(error_cert);
        X509_NAME_print_ex(outbio, subject, 0, XN_FLAG_MULTILINE);
        fprintf(stderr, "\n");
        exit(1);
    }

    fprintf(
        stderr,
        "%s: verify result: %s\n",
        argv[0],
        X509_verify_cert_error_string(ctx->error));

    ret = 0;

done:

    if (outbio)
        BIO_free_all(outbio);

    if (certbio)
        BIO_free_all(certbio);

    if (cert)
        X509_free(cert);

    if (error_cert)
        X509_free(error_cert);

    if (subject)
        X509_NAME_free(subject);

    if (ctx)
        X509_STORE_CTX_free(ctx);

    if (chain)
        sk_X509_pop_free(chain, X509_free);

    return ret;
}
