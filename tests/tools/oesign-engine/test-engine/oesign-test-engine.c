// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
//
// oesign-test-engine: minimal engine with predictable output to test oesign
// engine support

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

static const char test_engine_id[] = "oesign-test-engine";
static const char test_engine_name[] = "oesign test engine";

static EVP_PKEY* test_engine_only_privkey = NULL;
static EVP_PKEY* test_engine_only_pubkey = NULL;

static int _load_pem_file(const char* path, void** data, size_t* size)
{
    int rc = -1;
    FILE* is = NULL;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!path || !data || !size)
        goto done;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        *size = (size_t)st.st_size;
    }

    /* Allocate memory. We add 1 to null terminate the file since the crypto
     * libraries require null terminated PEM data. */
    if (*size == SIZE_MAX)
        goto done;

    if (!(*data = (uint8_t*)malloc(*size + 1)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(*data, 1, *size, is) != *size)
        goto done;

    /* Zero terminate the PEM data. */
    {
        uint8_t* data_tmp = (uint8_t*)*data;
        data_tmp[*size] = 0;
        *size += 1;
    }

    rc = 0;

done:

    if (rc != 0)
    {
        if (data && *data)
        {
            free(*data);
            *data = NULL;
        }

        if (size)
            *size = 0;
    }

    if (is)
        fclose(is);

    return rc;
}

/*
 * We pass the name of the pem file as the keyid, so that we can actually use
 * the signing key from the openenclave build as a signing key for oesign from
 * the test engine. We know the test went well when we can load a test enclave
 */
static EVP_PKEY* get_private_key_from_keyid(const char* keyid)
{
    uint8_t* pem_data = NULL;
    size_t pem_size = 0;
    EVP_PKEY* pkey = NULL;

    const char* path =
        keyid; // Do we want to directly do that or have an environment
               // variable to direct to a path for pem files?

    if (!_load_pem_file(path, (void**)&pem_data, &pem_size))
    {
        BIO* bio = NULL;

        if (!(bio = BIO_new_mem_buf(pem_data, (int)pem_size)))
        {
            goto err;
        }

        /* Read the key object */
        if (!(pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)))
        {
            goto err;
        }

        return pkey;
    }

err:
    return NULL;
}

static EVP_PKEY* test_engine_load_privkey(
    ENGINE* e,
    const char* keyid,
    UI_METHOD* ui_method,
    void* callback_data)
{
    (void)ui_method;
    (void)callback_data;
    printf("test_engine_load_privkey engine=%p, keyid = %s\n", e, keyid);

    EVP_PKEY* pkey = get_private_key_from_keyid(keyid);

    return pkey;
}

static EVP_PKEY* test_engine_load_pubkey(
    ENGINE* e,
    const char* keyid,
    UI_METHOD* ui_method,
    void* callback_data)
{
    (void)ui_method;
    (void)callback_data;
    printf("test_engine_load_pubkey engine=%p, keyid = %s\n", e, keyid);
    return test_engine_only_pubkey;
}

static int test_engine_init(ENGINE* e)
{
    int ret = 0;

    printf("test_engine_init\n");

    test_engine_only_privkey = EVP_PKEY_new();
    test_engine_only_pubkey = EVP_PKEY_new();
    if (!ENGINE_set_load_privkey_function(e, test_engine_load_privkey))
    {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto done;
    }
    if (!ENGINE_set_load_pubkey_function(e, test_engine_load_pubkey))
    {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto done;
    }

    ret = 1;

done:
    return ret;
}

static int test_engine_finish(ENGINE* e)
{
    (void)e;
    printf("test_engine_finish\n");
    return 1;
}

static int test_engine_destroy(ENGINE* e)
{
    (void)e;
    printf("test_engine_destroy\n");
    EVP_PKEY_free(test_engine_only_privkey);
    EVP_PKEY_free(test_engine_only_pubkey);
    return 1;
}

static int test_engine_bind(ENGINE* e, const char* id)
{
    int ret = 0;
    size_t idlen = sizeof(test_engine_id);

    if (id == NULL)
    {
        fprintf(stderr, "ENGINE_set_id failed. NULL id\n");
        goto done;
    }

    if (idlen < strlen(id))
    {
        idlen = strlen(id);
    }

    if (memcmp(id, test_engine_id, strlen(id)))
    {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto done;
    }

    if (!ENGINE_set_id(e, test_engine_id))
    {
        fprintf(
            stderr,
            "ENGINE_set_id failed. id %s does not match required id %s\n",
            id,
            test_engine_id);
        goto done;
    }

    if (!ENGINE_set_name(e, test_engine_name))
    {
        printf("ENGINE_set_name failed\n");
        goto done;
    }

    if (!ENGINE_set_destroy_function(e, test_engine_destroy) ||
        !ENGINE_set_init_function(e, test_engine_init) ||
        !ENGINE_set_finish_function(e, test_engine_finish))
    {
        goto done;
    }

    ret = 1;

done:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(test_engine_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
