// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/kdf.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "tests.h"
#include "utils.h"

// Custom test data
#define KEY_SIZE 32
#define TEST_FIXED_1 "0000000100"

#define TEST_LABEL_2 "test-key"
#define TEST_FIXED_2 "746573742d6b65790000000080"

#define TEST_LABEL_3 "test-key"
#define TEST_CONTEXT_3 "my-context"
#define TEST_FIXED_3 "746573742d6b6579006d792d636f6e7465787400000200"

// Test strings from the NIST database.
#define NIST_KEY_1 \
    "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0"
#define NIST_FIXED_1                                               \
    "01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e" \
    "46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac"
#define NIST_DERIVED_KEY_1 "10621342bfb0fd40046c0e29f2cfdbf0"

#define NIST_KEY_2 \
    "32c4003872a146194023eac1bda74ddf2b66977dad8a554b974ca2a62f7e4f43"
#define NIST_FIXED_2                                               \
    "33d8cf6d0c759fb622d867ea8cf1285de4020af81cc287addf38cc2da464" \
    "3e6db3b215ad3e33bfc47877c3620e336887c3c9ad4a1c6c0476b0f90a33"
#define NIST_DERIVED_KEY_2 "f593af0e1a492a7b904a2662897fa1c1"

#define NIST_KEY_3 \
    "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6"
#define NIST_FIXED_3                                               \
    "7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc" \
    "1a6293580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80"
#define NIST_DERIVED_KEY_3 \
    "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779"

#define NIST_KEY_4 \
    "aeeeca60f689a441b13b0cbcd441d82df0cf87dac236290dece8931df8d70317"
#define NIST_FIXED_4                                               \
    "588ec041e5733b7031212c5538efe4f6aafa4cda8b925d261f5a2688f007" \
    "b3ac240ee12991e77b8cb8538678615966164a81872bd1cfcbfb39a4f450"
#define NIST_DERIVED_KEY_4 \
    "3e81d6113cee3c529ecedff89a6999ce25b618c15ee1d19d45cb376a1c8e2374"

#define NIST_KEY_5 \
    "dc60338d884eecb72975c603c27b360605011756c697c4fc388f5176ef81efb1"
#define NIST_FIXED_5                                               \
    "44d7aa08feba26093c14979c122c2437c3117b63b78841cd10a4bc5ed55c" \
    "56586ad8986d55307dca1d198edcffbc516a8fbe6152aa428cdd800c062d"
#define NIST_DERIVED_KEY_5 "29ac07dccf1f28d506cd623e6e3fc2fa255bd60b"

#define NIST_KEY_6 \
    "7a7ecee4f04c1f5453f29b8c65bee909f673c44f65e8f9cc18c31c32e9bcfc5a"
#define NIST_FIXED_6                                               \
    "0e2b53dd63008e0663962a25da9cd55fc2ea377148783da229ff7e3bd614" \
    "2a43c854b6b5d06d87b535936f1edc7cd067e8dbba220a1f9a5932b32a64"
#define NIST_DERIVED_KEY_6 "96fb8ef9380ac9de2711ef5a83249e608dc7bffc"

#define NIST_KEY_7 \
    "c4bedbddb66493e7c7259a3bbbc25f8c7e0ca7fe284d92d431d9cd99a0d214ac"
#define NIST_FIXED_7                                               \
    "1c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220e" \
    "acace6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b"
#define NIST_DERIVED_KEY_7                     \
    "1da47638d6c9c4d04d74d4640bbd42ab814d9e8c" \
    "c22f4326695239f96b0693f12d0dd1152cf44430"

#define NIST_KEY_8 \
    "22256ca571d5c896db80a8758ff81cf8631d2bc38c7e76f3bafb0c2af540a356"
#define NIST_FIXED_8                                               \
    "9dd2dcd97b926251b50c6111d988e2951b02accc143702c88920cf36848f" \
    "7c731756ab0537cb26e22725f11de069e5335802b0cb56c158dd75014791"
#define NIST_DERIVED_KEY_8                     \
    "a11aa3b1a93d2ce117550866c28d6974cf626719" \
    "385b8868101a71a5d2aa793bc23c3cfdebe52ec9"

typedef struct _fixed_test_data
{
    const char* label;
    const char* context;
    size_t output_size;
    const char* fixed;
} fixed_test_data_t;

typedef struct _key_test_data
{
    const char* key;
    const char* data;
    const char* derived_key;
    size_t output_size;
} key_test_data_t;

static fixed_test_data_t FIXED_TESTS[] = {
    {NULL, NULL, KEY_SIZE, TEST_FIXED_1},
    {TEST_LABEL_2, NULL, KEY_SIZE / 2, TEST_FIXED_2},
    {TEST_LABEL_3, TEST_CONTEXT_3, KEY_SIZE * 2, TEST_FIXED_3},
};

static key_test_data_t KEY_TESTS[] = {
    {NIST_KEY_1, NIST_FIXED_1, NIST_DERIVED_KEY_1, 16},
    {NIST_KEY_2, NIST_FIXED_2, NIST_DERIVED_KEY_2, 16},
    {NIST_KEY_3, NIST_FIXED_3, NIST_DERIVED_KEY_3, 32},
    {NIST_KEY_4, NIST_FIXED_4, NIST_DERIVED_KEY_4, 32},
    {NIST_KEY_5, NIST_FIXED_5, NIST_DERIVED_KEY_5, 20},
    {NIST_KEY_6, NIST_FIXED_6, NIST_DERIVED_KEY_6, 20},
    {NIST_KEY_7, NIST_FIXED_7, NIST_DERIVED_KEY_7, 40},
    {NIST_KEY_8, NIST_FIXED_8, NIST_DERIVED_KEY_8, 40},
};

static void _test_create_fixed(void)
{
    size_t iters = sizeof(FIXED_TESTS) / sizeof(FIXED_TESTS[0]);
    for (size_t i = 0; i < iters; i++)
    {
        uint8_t* custom_fixed = NULL;
        size_t custom_fixed_size = 0;
        uint8_t expected[(sizeof(TEST_FIXED_3) - 1) / 2];
        const char* label = FIXED_TESTS[i].label;
        const char* context = FIXED_TESTS[i].context;

        hex_to_buf(FIXED_TESTS[i].fixed, expected, sizeof(expected));
        OE_TEST(
            oe_kdf_create_fixed_data(
                (const uint8_t*)label,
                label ? strlen(label) : 0,
                (const uint8_t*)context,
                context ? strlen(context) : 0,
                FIXED_TESTS[i].output_size,
                &custom_fixed,
                &custom_fixed_size) == OE_OK);

        OE_TEST(custom_fixed != NULL);
        OE_TEST(custom_fixed_size <= sizeof(expected));
        OE_TEST(memcmp(expected, custom_fixed, custom_fixed_size) == 0);
        free(custom_fixed);
    }
}

static void _test_key_gen(void)
{
    uint8_t key[32];
    uint8_t fixed_data[60];
    uint8_t derived_key[64];
    uint8_t key_expected[64];

    for (size_t i = 0; i < sizeof(KEY_TESTS) / sizeof(KEY_TESTS[0]); i++)
    {
        hex_to_buf(KEY_TESTS[i].key, key, sizeof(key));
        hex_to_buf(KEY_TESTS[i].data, fixed_data, sizeof(fixed_data));
        hex_to_buf(
            KEY_TESTS[i].derived_key, key_expected, sizeof(key_expected));

        OE_TEST(
            oe_kdf_derive_key(
                OE_KDF_HMAC_SHA256_CTR,
                key,
                sizeof(key),
                fixed_data,
                sizeof(fixed_data),
                derived_key,
                KEY_TESTS[i].output_size) == OE_OK);

        OE_TEST(
            memcmp(derived_key, key_expected, KEY_TESTS[i].output_size) == 0);
    }
}

// Test compution of KDF over multiple NIST test strings.
void TestKDF(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    // Run a test creating custom fixed data.
    _test_create_fixed();
    _test_key_gen();

    printf("=== passed %s()\n", __FUNCTION__);
}
