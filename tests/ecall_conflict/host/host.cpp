// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>

#include <openenclave/internal/tests.h>
#include "../../../host/ecall_ids.h"
// Ensure that there are no multiple definition errors for user defined types.
#include "enc1_u.h"
#include "enc2_u.h"

MyStruct g_s = {5, 6};
MyUnion g_u = {7};
MyEnum g_e = GREEN;

void host_ocall1(MyStruct s)
{
    OE_TEST(s.x == g_s.x);
    OE_TEST(s.y == g_s.y);
}

void host_ocall2(MyUnion u)
{
    OE_TEST(u.y == g_u.y);
}

void host_ocall3(MyEnum e)
{
    OE_TEST(e == g_e);
}

int main(int argc, char** argv)
{
    oe_enclave_t* enc1 = NULL;
    oe_enclave_t* enc2 = NULL;

    const uint32_t flags = oe_get_create_flags();
    uint64_t global_id = OE_GLOBAL_ECALL_ID_NULL;
    uint64_t local_id = OE_UINT64_MAX;
    int val;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE1_PATH ENCLAVE2_PATH\n", argv[0]);
        return 1;
    }

    OE_TEST(
        oe_create_enc1_enclave(
            argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enc1) == OE_OK);

    /*
     * Use the internal APIs to test the global and local ids.
     * At this point the expected global table should be:
     * global id 0 - "enc_local_ecall1"
     * global id 1 - "enc_ecall1"
     * global id 2 - "enc_ecall2"
     * global id 3 - "enc_ecall3"
     * The local (per-enclave) table should be:
     * [global id 0]: 0
     * [global id 1]: 1
     * [global id 2]: 2
     * [global id 3]: 3
     */
    OE_TEST(oe_get_global_id("enc_local_ecall1", &global_id) == OE_OK);
    OE_TEST(global_id == 0);
    OE_TEST(oe_get_global_id("enc_ecall1", &global_id) == OE_OK);
    OE_TEST(global_id == 1);
    OE_TEST(oe_get_global_id("enc_ecall2", &global_id) == OE_OK);
    OE_TEST(global_id == 2);
    OE_TEST(oe_get_global_id("enc_ecall3", &global_id) == OE_OK);
    OE_TEST(global_id == 3);

    /* Look up by global id. The name should not be NULL. */
    global_id = 0;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_local_ecall1", &global_id, &local_id) ==
        OE_OK);
    OE_TEST(local_id == 0);
    global_id = 1;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_ecall1", &global_id, &local_id) == OE_OK);
    OE_TEST(local_id == 1);
    global_id = 2;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_ecall2", &global_id, &local_id) == OE_OK);
    OE_TEST(local_id == 2);
    global_id = 3;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_ecall3", &global_id, &local_id) == OE_OK);
    OE_TEST(local_id == 3);

    /* Look up by name. The global id will be set. */
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_local_ecall1", &global_id, &local_id) ==
        OE_OK);
    OE_TEST(global_id == 0);
    OE_TEST(local_id == 0);
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_ecall1", &global_id, &local_id) == OE_OK);
    OE_TEST(global_id == 1);
    OE_TEST(local_id == 1);
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_ecall2", &global_id, &local_id) == OE_OK);
    OE_TEST(global_id == 2);
    OE_TEST(local_id == 2);
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc1, "enc_ecall3", &global_id, &local_id) == OE_OK);
    OE_TEST(global_id == 3);
    OE_TEST(local_id == 3);

    OE_TEST(
        oe_create_enc2_enclave(
            argv[2], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enc2) == OE_OK);

    /* Assert id of last imported system ecall, Since the first enclave imports
     * system edls, the system ecalls will take up the next few global ids. */
    uint64_t last_system_ecall_id = 0;
    OE_TEST(
        oe_get_global_id(
            "oe_sgx_switchless_enclave_worker_thread_ecall",
            &last_system_ecall_id) == OE_OK);
    OE_TEST(last_system_ecall_id == 8);

    /*
     * Use the internal APIs to test the global and local ids.
     *  After creating enc2, the expected global table should be:
     * global id 0 - "enc_local_ecall1"
     * global id 1 - "enc_ecall1"
     * global id 2 - "enc_ecall2"
     * global id 3 - "enc_ecall3"
     * system ecalls ...
     * global id 9 - "enc_local_ecall2"
     * The local (per-enclave) table should be:
     * [global id 0]: ECALL_ID_NULL
     * [global id 1]: 2
     * [global id 2]: 1
     * [global id 3]: ECALL_ID_NULL
     * ... (system ecalls)
     * [global id 9]: 0
     */
    OE_TEST(oe_get_global_id("enc_local_ecall1", &global_id) == OE_OK);
    OE_TEST(global_id == 0);
    OE_TEST(oe_get_global_id("enc_ecall1", &global_id) == OE_OK);
    OE_TEST(global_id == 1);
    OE_TEST(oe_get_global_id("enc_ecall2", &global_id) == OE_OK);
    OE_TEST(global_id == 2);
    OE_TEST(oe_get_global_id("enc_ecall3", &global_id) == OE_OK);
    OE_TEST(global_id == 3);
    OE_TEST(oe_get_global_id("enc_local_ecall2", &global_id) == OE_OK);
    OE_TEST(global_id == 9);

    /*
     * Look up by global id. The name should not be NULL.
     * The result of using "enc_local_ecall1" and "enc_ecall3" should
     * return OE_NOT_FOUND.
     */
    global_id = 0;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_local_ecall1", &global_id, &local_id) ==
        OE_NOT_FOUND);
    OE_TEST(local_id == OE_ECALL_ID_NULL);
    global_id = 1;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_ecall1", &global_id, &local_id) == OE_OK);
    OE_TEST(local_id == 2);
    global_id = 2;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_ecall2", &global_id, &local_id) == OE_OK);
    OE_TEST(local_id == 1);
    global_id = 3;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_ecall3", &global_id, &local_id) ==
        OE_NOT_FOUND);
    OE_TEST(local_id == OE_ECALL_ID_NULL);
    global_id = 9;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_local_ecall2", &global_id, &local_id) ==
        OE_OK);
    OE_TEST(local_id == 0);

    /* Look up by name. The global id will be set. */
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_local_ecall1", &global_id, &local_id) ==
        OE_NOT_FOUND);
    OE_TEST(global_id == 0);
    OE_TEST(local_id == OE_ECALL_ID_NULL);
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_ecall1", &global_id, &local_id) == OE_OK);
    OE_TEST(global_id == 1);
    OE_TEST(local_id == 2);
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_ecall2", &global_id, &local_id) == OE_OK);
    OE_TEST(global_id == 2);
    OE_TEST(local_id == 1);
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_ecall3", &global_id, &local_id) ==
        OE_NOT_FOUND);
    OE_TEST(global_id == 3);
    OE_TEST(local_id == OE_ECALL_ID_NULL);
    global_id = OE_GLOBAL_ECALL_ID_NULL;
    OE_TEST(
        oe_get_ecall_ids(enc2, "enc_local_ecall2", &global_id, &local_id) ==
        OE_OK);
    OE_TEST(global_id == 9);
    OE_TEST(local_id == 0);

    /* Make the normal ecalls. */

    // Call functions in enclave 1.
    OE_TEST(enc_ecall1(enc1, g_s) == OE_OK);
    OE_TEST(enc_ecall2(enc1, g_u) == OE_OK);
    OE_TEST(enc_ecall3(enc1, g_e) == OE_OK);

    // Change values for enclave 2.
    g_s = {8, 9};
    g_u.y = 10;
    OE_TEST(enc_ecall1(enc2, g_s) == OE_OK);
    OE_TEST(enc_ecall2(enc2, g_u) == OE_OK);

    OE_TEST(enc_local_ecall1(enc1, &val, 11) == OE_OK);
    OE_TEST(val == 12);
    OE_TEST(enc_local_ecall2(enc2, &val, 13) == OE_OK);
    OE_TEST(val == 14);

    OE_TEST(oe_terminate_enclave(enc1) == OE_OK);
    OE_TEST(oe_terminate_enclave(enc2) == OE_OK);

    printf("=== passed all tests (call_conflict)\n");
}
