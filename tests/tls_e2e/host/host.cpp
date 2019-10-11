// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_e2e_u.h"

#define SERVER_PORT "12345"
#define SERVER_IP "127.0.0.1"

#define POSITIVE_TEST false
#define NEGATIVE_TEST true
#define SKIP_RETURN_CODE 2

// A fatal error occured, eg the chain is too long or the vrfy callback failed
#define FATAL_TLS_HANDSHAKE_ERROR -0x3000

typedef struct _tls_thread_context_config
{
    oe_enclave_t* enclave;
    struct tls_control_args args;
} tls_thread_context_config_t;

typedef struct _tls_test_configs
{
    tls_thread_context_config_t server;
    tls_thread_context_config_t client;
} tls_test_configs_t;

typedef struct _test_cases_config
{
    const char* name;
    struct tls_control_args args;
    bool negative_test;
} test_cases_config_t;

typedef enum test_target
{
    server_target = 0,
    client_target,
    max_test_target_count
} test_target_t;

typedef enum test_config_type
{
    config_type_no_fault_injection = 0,
    config_type_fail_oe_verify_tls_cert_scenario,
    config_type_fail_cert_verify_callback_scenario,
    config_type_fail_enclave_identity_verifier_callback_scenario,
    max_test_config_type_count
} test_config_type_t;

oe_enclave_t* g_server_enclave = NULL;
oe_enclave_t* g_client_enclave = NULL;
int g_server_thread_exit_code = 0;
int g_client_thread_exit_code = 0;
pthread_mutex_t server_mutex;
pthread_cond_t server_cond;
bool g_server_condition = false;
pthread_t server_thread_id;

int server_is_ready()
{
    OE_TRACE_INFO("TLS server_is_ready!\n");
    pthread_mutex_lock(&server_mutex);
    g_server_condition = true;
    pthread_cond_signal(&server_cond);
    pthread_mutex_unlock(&server_mutex);
    return 1;
}

oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    OE_TRACE_INFO(
        "identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        OE_TRACE_ERROR(
            "identity.security_version check failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // the unique ID for the enclave
    // For SGX enclaves, this is the MRENCLAVE value
    OE_TRACE_INFO("identity->unique_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->unique_id[i]);

    // The signer ID for the enclave.
    // For SGX enclaves, this is the MRSIGNER value
    OE_TRACE_INFO("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    // The Product ID for the enclave.
    // For SGX enclaves, this is the ISVPRODID value
    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

void* server_thread(void* arg)
{
    oe_result_t result = OE_FAILURE;
    tls_thread_context_config_t* config = &(((tls_test_configs_t*)arg)->server);

    OE_TRACE_INFO("Server thread starting\n");
    g_server_condition = false;

    result = setup_tls_server(
        config->enclave,
        &g_server_thread_exit_code,
        &(config->args),
        (char*)SERVER_PORT);
    OE_CHECK_MSG(
        result,
        "Invoking ecall setup_tls_server() failed: result=%s\n",
        oe_result_str(result));

    OE_TRACE_INFO(
        "setup_tls_server(): g_server_thread_exit_code=[%d]\n",
        g_server_thread_exit_code);
    if (config->args.fail_cert_verify_callback ||
        config->args.fail_enclave_identity_verifier_callback ||
        config->args.fail_oe_verify_attestation_certificate)
    {
        OE_TEST(g_server_thread_exit_code == FATAL_TLS_HANDSHAKE_ERROR);
        g_server_thread_exit_code = 0;
    }

    OE_TRACE_INFO("Leaving server thread...\n");
    fflush(stdout);
    pthread_exit((void*)&g_server_thread_exit_code);
done:
    return NULL;
}

void* client_thread(void* arg)
{
    oe_result_t result = OE_FAILURE;
    tls_thread_context_config_t* client_config =
        &(((tls_test_configs_t*)arg)->client);
    tls_thread_context_config_t* server_config =
        &(((tls_test_configs_t*)arg)->server);
    void* retval = NULL;

    OE_TRACE_INFO("Client thread: call launch_tls_client()\n");
    result = launch_tls_client(
        client_config->enclave,
        &g_client_thread_exit_code,
        &(client_config->args),
        (char*)SERVER_IP,
        (char*)SERVER_PORT);
    OE_CHECK_MSG(
        result,
        "Invoking ecall launch_tls_client() failed: result=%s\n",
        oe_result_str(result));

    OE_TRACE_INFO(
        "launch_tls_client() g_client_thread_exit_code=[%d]\n",
        g_client_thread_exit_code);

    if (client_config->args.fail_cert_verify_callback ||
        client_config->args.fail_enclave_identity_verifier_callback ||
        client_config->args.fail_oe_verify_attestation_certificate)
        OE_TEST(g_client_thread_exit_code != 0);

    OE_TRACE_INFO("Waiting for the server thread to terminate...\n");
    // block client thread until the server thread is done
    pthread_join(server_thread_id, (void**)&retval);

    // enforce server return value
    OE_TRACE_INFO("server returns retval = [%d]\n", *(int*)retval);

    if (server_config->args.fail_cert_verify_callback ||
        server_config->args.fail_enclave_identity_verifier_callback ||
        server_config->args.fail_oe_verify_attestation_certificate)
    {
        // since this test ignores SIGPIPE, ther client thread will terminiate
        // with 0
        OE_TEST(*(int*)(retval) == 0);
    }

    // In the no-fault-injection test case, the client thread should return
    // cleanly (0)
    if (!client_config->args.fail_cert_verify_callback &&
        !client_config->args.fail_enclave_identity_verifier_callback &&
        !client_config->args.fail_oe_verify_attestation_certificate &&
        !server_config->args.fail_cert_verify_callback &&
        !server_config->args.fail_enclave_identity_verifier_callback &&
        !server_config->args.fail_oe_verify_attestation_certificate)
    {
        OE_TEST(g_client_thread_exit_code == 0);
    }
    else
    {
        // g_client_thread_exit_code could be any values in negative test cases
        g_client_thread_exit_code = 0;
    }
    pthread_exit((void*)&g_client_thread_exit_code);
    fflush(stdout);
done:
    return NULL;
}

int run_test_with_config(tls_test_configs_t* test_configs)
{
    pthread_attr_t server_tattr;
    pthread_attr_t client_tattr;
    pthread_t client_thread_id;
    int ret = 0;
    void* retval = NULL;

    // create server thread
    ret = pthread_attr_init(&server_tattr);
    if (ret)
        oe_put_err("pthread_attr_init(server): ret=%u", ret);

    ret = pthread_create(
        &server_thread_id, NULL, server_thread, (void*)test_configs);
    if (ret)
        oe_put_err("pthread_create(server): ret=%u", ret);

    OE_TRACE_INFO("wait until TLS server is ready to accept client request\n");
    pthread_mutex_lock(&server_mutex);
    while (!g_server_condition)
        pthread_cond_wait(&server_cond, &server_mutex);
    pthread_mutex_unlock(&server_mutex);

    fflush(stdout);

    // create client thread
    ret = pthread_attr_init(&client_tattr);
    if (ret)
        oe_put_err("pthread_attr_init(client): ret=%u", ret);

    ret = pthread_create(
        &client_thread_id, NULL, client_thread, (void*)test_configs);
    if (ret)
        oe_put_err("pthread_create(client): ret=%u", ret);

    pthread_join(client_thread_id, &retval);
    ret = *(int*)retval;
    OE_TRACE_INFO("Client thread terminated with ret =%d... \n", ret);
    return ret;
}

int run_scenarios_tests()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    test_cases_config_t unittests_configs[4] = {
        {"\n------positive_test\n", {false, false, false}, POSITIVE_TEST},
        {"\n------negative_fail_oe_verify_attestation_certificate\n",
         {true, false, false},
         NEGATIVE_TEST},
        {"\n------negative_fail_cert_verify_callback\n",
         {false, true, false},
         NEGATIVE_TEST},
        {"\n------negative_fail_enclave_identity_verifier_callback\n",
         {false, false, true},
         NEGATIVE_TEST}};

    signal(SIGPIPE, SIG_IGN);
    test_configs.server.enclave = g_server_enclave;
    test_configs.client.enclave = g_client_enclave;

    // Each of above test config got exercised on both client and server roles
    for (test_target_t i = server_target; i < max_test_target_count;
         i = test_target_t(i + 1))
    {
        for (test_config_type_t j = config_type_no_fault_injection;
             j < max_test_config_type_count;
             j = test_config_type_t(j + 1))
        {
            g_server_thread_exit_code = 0;
            g_client_thread_exit_code = 0;
            g_server_condition = false;

            if (i == server_target)
            {
                test_configs.server.args = unittests_configs[j].args;
                test_configs.client.args =
                    unittests_configs[config_type_no_fault_injection].args;
            }
            else
            {
                test_configs.server.args =
                    unittests_configs[config_type_no_fault_injection].args;
                test_configs.client.args = unittests_configs[j].args;
            }
            printf(
                "Test case: %s:%s ",
                (i == server_target) ? "Server" : "Client",
                unittests_configs[j].name);

            printf(
                "This is a %s test case. Expect %s errors\n",
                (unittests_configs[j].negative_test ? "negative" : "positive"),
                (unittests_configs[j].negative_test ? "" : "no"));

            ret = run_test_with_config(&test_configs);
            if (ret)
            {
                OE_TRACE_ERROR(
                    "run_test_with_config failed with ret=%d\n", ret);
                goto done;
            }
            OE_TRACE_INFO(" test succeeded\n");
        }
    }
done:
    return ret;
}

int main(int argc, const char* argv[])
{
#ifdef OE_LINK_SGX_DCAP_QL
    oe_result_t result = OE_FAILURE;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    int ret = 0;

    if (argc != 3)
    {
        OE_TRACE_ERROR("Usage: %s server_enc client_enc\n", argv[0]);
        goto done;
    }
    // the following call setup the host resolver, which is needed
    // for getaddrinfo to work
    // oe_resolver_install_hostresolver();

    flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    if ((result = oe_create_tls_e2e_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             NULL,
             0,
             &g_server_enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    if ((result = oe_create_tls_e2e_enclave(
             argv[2],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             NULL,
             0,
             &g_client_enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    ret = run_scenarios_tests();
    if (ret)
        oe_put_err("run_scenarios_tests(): failed with ret=%d", ret);

    result = OE_OK;
done:
    result = oe_terminate_enclave(g_client_enclave);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(g_server_enclave);
    OE_TEST(result == OE_OK);

    OE_TRACE_INFO("=== passed all tests (tls)\n");

    return 0;
#else
    // this test should not run on any platforms where OE_LINK_SGX_DCAP_QL is
    // not defined
    OE_UNUSED(argc);
    OE_UNUSED(argv);
    OE_TRACE_INFO(
        "=== tests skipped when built with OE_LINK_SGX_DCAP_QL=OFF\n");
    return SKIP_RETURN_CODE;
#endif
}
