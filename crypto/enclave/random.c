#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/random.h>
#include <openenclave/enclave.h>

OE_Result OE_Random(void* data, size_t size)
{
    OE_Result result = OE_FAILURE;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if (mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        goto done;
    }

    if (mbedtls_ctr_drbg_random(&ctr_drbg, data, size) != 0)
        goto done;

    result = OE_OK;

done:

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return result;
}
