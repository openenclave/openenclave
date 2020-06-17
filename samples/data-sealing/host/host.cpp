// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <common/shared.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <iostream>
#include <vector>
#include "datasealing_u.h"

using namespace std;

#define GET_POLICY_NAME(policy) \
    ((policy == POLICY_UNIQUE) ? "POLICY_UNIQUE" : "POLICY_PRODUCT")

const char* g_plain_text = "test plaintext";
const char* g_opt_msg = "optional sealing message";

oe_enclave_t* create_enclave(const char* enclavePath)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Loading enclave library %s\n", enclavePath);
    oe_result_t result = oe_create_datasealing_enclave(
        enclavePath,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_datasealing_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: enclave terminated.\n");
}

int unseal_data_and_verify_result(
    oe_enclave_t* target_enclave,
    sealed_data_t* sealed_data,
    size_t sealed_data_size,
    unsigned char* target_data,
    size_t target_data_size)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;
    unsigned char* data = NULL;
    size_t data_size = 0;

    cout << "Host: enter unseal_data_and_verify_result " << endl;

    result = unseal_data(
        target_enclave, &ret, sealed_data, sealed_data_size, &data, &data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Host: ecall unseal_data returned " << oe_result_str(result)
             << " ret = " << ret << (ret ? " (failed)" : "(success)") << endl;
        goto exit;
    }

    // print unsealed data
    cout << "Host: Unsealed result:" << endl;
    printf("data=%s\n", data);

    printf("data_size=%zd\n", data_size);
    printf("target_data_size=%zd\n", target_data_size);

    if (strncmp(
            (const char*)data, (const char*)target_data, target_data_size) != 0)
    {
        cout << "Host: Unsealed data is not equal to the original data."
             << endl;
        ret = ERROR_UNSEALED_DATA_FAIL;
        result = OE_FAILURE;
        goto exit;
    }
exit:
    if (data)
        free(data);

    if (ret != 0)
        result = OE_FAILURE;

    cout << "Host: exit unseal_data_and_verify_result with "
         << oe_result_str(result) << endl;
    return ret;
}

oe_result_t seal_unseal_by_policy(
    int policy,
    oe_enclave_t* enclave_a_v1,
    oe_enclave_t* enclave_a_v2,
    oe_enclave_t* enclave_b)
{
    oe_result_t result = OE_OK;
    unsigned char* data = NULL;
    size_t data_size = 0;
    sealed_data_t* sealed_data = NULL;
    size_t sealed_data_size = 0;
    int ret = 0;

    // Seal data into enclave_a_v1
    cout << "Host: Seal data into enclave_a_v1 with " << GET_POLICY_NAME(policy)
         << endl;

    data = (unsigned char*)g_plain_text;
    data_size = strlen((const char*)data) + 1;

    // Sealing and unsealing from the same enclave should work for both
    // POLICY_UNIQUE and POLICY_PRODUCT
    // On a successful return, the memory pointed by the sealed_data was
    // allocated by the enclave. The host needs to free it.
    result = seal_data(
        enclave_a_v1,
        &ret,
        policy,
        (unsigned char*)g_opt_msg,
        strlen(g_opt_msg),
        data,
        data_size,
        &sealed_data,
        &sealed_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Host: seal_data failed with " << oe_result_str(result)
             << " ret = " << ret << endl;
        goto exit;
    }
    cout << "Host: data successfully sealed" << endl;

    // Unseal data in the same enclave it was sealed
    cout << "\n\nHost: Unseal data in the same enclave it was sealed " << endl;
    ret = unseal_data_and_verify_result(
        enclave_a_v1,
        sealed_data,
        sealed_data_size,
        (unsigned char*)g_plain_text,
        data_size);
    if (ret != 0)
    {
        cout << "Host: Validation of unsealed data failed with ret = " << ret
             << endl;
        goto exit;
    }
    cout << "Host: Succeeded: sealing and unsealing data on the same enclave "
            "worked as expected "
         << endl;
    ret = 0;

    // Unsealing data in a different enclave from the same product:
    // For POLICY_UNIQUE: this is expected to fail because with POLICY_UNIQUE
    // sealing policy, it seals the data with a key unique to the enclave and it
    // cannot be unsealed from any other  enclave even it's from the same
    // product
    // For POLICY_PRODUCT: this is expected to succeed. POLICY_PRODUCT sealing
    // policy ensures sealed data could be unsealed by enclaves from the product
    cout << "\n\nHost: Unseal data in an different enclave from the same "
            "product:"
         << "Seal policy is " << GET_POLICY_NAME(policy) << "--> failure is "
         << ((policy == POLICY_UNIQUE) ? "expected" : "not expected") << endl;
    ret = unseal_data_and_verify_result(
        enclave_a_v2,
        sealed_data,
        sealed_data_size,
        (unsigned char*)g_plain_text,
        data_size);
    if (policy == POLICY_UNIQUE)
    {
        if (ret != ERROR_SIGNATURE_VERIFY_FAIL)
        {
            cout << "Host: failed to return ERROR_SIGNATURE_VERIFY_FAIL (ret) "
                    "for POLICY_UNIQUE"
                 << ret << endl;
            goto exit;
        }
    }
    else if (policy == POLICY_PRODUCT)
    {
        if (ret != 0)
        {
            cout << "Host: failed to unseal data for the POLICY_PRODUCT" << ret
                 << endl;
            goto exit;
        }
    }
    cout << "Host: operation succeeded: unseal data from a different enclave "
            "of the same product."
         << endl;
    ret = 0;

    // Unsealing the data in an enclave with a different product identity is
    // expected to fail
    cout << "\n\nHost: Unseal data in a different enclave from a diffent "
            "product: failure is expected"
         << endl;
    ret = unseal_data_and_verify_result(
        enclave_b,
        sealed_data,
        sealed_data_size,
        (unsigned char*)g_plain_text,
        data_size);
    if (ret != ERROR_SIGNATURE_VERIFY_FAIL)
    {
        cout << "Host: failed to return ERROR_SIGNATURE_VERIFY_FAIL " << endl;
        goto exit;
    }
    ret = 0;
    cout << "Host: operation succeeded: completed as expected" << endl;

    result = OE_OK;

exit:

    // Free host memory allocated by the enclave.
    if (sealed_data != NULL)
        free(sealed_data);

    if (ret != 0)
        result = OE_FAILURE;

    return result;
}

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;
    oe_enclave_t* enclave_a_v1 = NULL;
    oe_enclave_t* enclave_a_v2 = NULL;
    oe_enclave_t* enclave_b = NULL;
    int ret = 1;

    cout << "Host: enter main" << endl;
    if (argc != 4)
    {
        cout << "Usage: " << argv[0] << " enclave1  enclave2 enclave3" << endl;
        goto exit;
    }

    // Instantiate three different enclaves from two different products
    // Product A:  enclave_a_v1 and enclave_a_v2
    // Product B:  enclave_b
    // Note: All enclaves from the same product were signed by the same
    // cerificate authority, that is, signed with the same private.pem file in
    // this sample
    enclave_a_v1 = create_enclave(argv[1]);
    if (enclave_a_v1 == NULL)
    {
        goto exit;
    }

    enclave_a_v2 = create_enclave(argv[2]);
    if (enclave_a_v2 == NULL)
    {
        goto exit;
    }

    enclave_b = create_enclave(argv[3]);
    if (enclave_a_v2 == NULL)
    {
        goto exit;
    }

    //  POLICY_UNIQUE policy
    cout << "------------------------------------------------\n";
    cout << "Host: Sealing data with POLICY_UNIQUE policy\n";
    cout << "------------------------------------------------\n";
    result = seal_unseal_by_policy(
        POLICY_UNIQUE, enclave_a_v1, enclave_a_v2, enclave_b);
    if (result != OE_OK)
    {
        cout << "Host: Data sealing with POLICY_UNIQUE failed!" << ret << endl;
        goto exit;
    }

    //  POLICY_PRODUCT policy
    cout << "------------------------------------------------\n";
    cout << "Host: Sealing data with POLICY_PRODUCT policy\n";
    cout << "------------------------------------------------\n";
    result = seal_unseal_by_policy(
        POLICY_PRODUCT, enclave_a_v1, enclave_a_v2, enclave_b);
    if (result != OE_OK)
    {
        cout << "Host: Data sealing with POLICY_UNIQUE failed!" << ret << endl;
        goto exit;
    }
    ret = 0;

exit:
    cout << "Host: Terminating enclaves" << endl;
    if (enclave_a_v1)
        terminate_enclave(enclave_a_v1);

    if (enclave_a_v2)
        terminate_enclave(enclave_a_v2);

    if (enclave_b)
        terminate_enclave(enclave_b);

    if (ret == 0)
        cout << "Host: Sample completed successfully." << endl;

    return ret;
}
