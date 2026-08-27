// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>

#include "../../../common/attest_plugin.h"
#include "plugin_u.h"

class Gate
{
  public:
    void pause()
    {
        std::unique_lock<std::mutex> lock(_mutex);
        _entered = true;
        _condition.notify_all();
        OE_TEST(_condition.wait_for(
            lock, std::chrono::seconds(30), [this] { return _released; }));
    }

    void wait()
    {
        std::unique_lock<std::mutex> lock(_mutex);
        OE_TEST(_condition.wait_for(
            lock, std::chrono::seconds(30), [this] { return _entered; }));
    }

    void release()
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _released = true;
        _condition.notify_all();
    }

  private:
    std::mutex _mutex;
    std::condition_variable _condition;
    bool _entered = false;
    bool _released = false;
};

static Gate _report_gate;

extern "C" void pause_report_dispatch()
{
    _report_gate.pause();
}

extern "C" void
host_verify(const oe_uuid_t*, bool, uint8_t*, size_t, uint8_t*, size_t)
{
    OE_TEST(false);
}

static oe_result_t _on_register(oe_attestation_role_t*, const void*, size_t)
{
    // Registration callbacks run under the recursive registry lock.
    OE_TEST(oe_attest_acquire_registry(OE_ATTEST_ROLE_ATTESTER) == OE_OK);
    oe_attest_release_plugin(OE_ATTEST_ROLE_ATTESTER);
    return OE_OK;
}

static oe_result_t _on_unregister(oe_attestation_role_t*)
{
    return OE_OK;
}

static void _test_registry(oe_attest_role_type_t role)
{
    oe_plugin_list_node_t* list = nullptr;
    oe_attestation_role_t plugins[2] = {};
    for (size_t i = 0; i < 2; ++i)
    {
        plugins[i].format_id.b[0] = static_cast<uint8_t>(i + 1);
        plugins[i].on_register = _on_register;
        plugins[i].on_unregister = _on_unregister;
        OE_TEST(
            oe_attest_register_plugin(&list, &plugins[i], nullptr, 0) == OE_OK);
    }

    Gate gate;
    std::thread dispatch([&] {
        oe_attestation_role_t* plugin = nullptr;
        OE_TEST(
            oe_attest_acquire_plugin(
                role, &list, &plugins[0].format_id, &plugin) == OE_OK);
        gate.pause();
        OE_TEST(plugin == &plugins[0]);
        OE_TEST(plugin->on_register(plugin, nullptr, 0) == OE_OK);
        oe_attest_release_plugin(role);
    });

    gate.wait();
    OE_TEST(oe_attest_begin_shutdown(role) == OE_BUSY);
    OE_TEST(oe_attest_unregister_plugin(role, &list, &plugins[1]) == OE_BUSY);
    OE_TEST(list && list->next && !list->next->next);

    const auto other_role = role == OE_ATTEST_ROLE_ATTESTER
                                ? OE_ATTEST_ROLE_VERIFIER
                                : OE_ATTEST_ROLE_ATTESTER;
    OE_TEST(oe_attest_begin_shutdown(other_role) == OE_OK);
    oe_attest_end_shutdown();
    gate.release();
    dispatch.join();

    oe_attestation_role_t* missing = &plugins[0];
    const oe_uuid_t unknown = {};
    OE_TEST(
        oe_attest_acquire_plugin(role, &list, &unknown, &missing) ==
        OE_NOT_FOUND);
    OE_TEST(missing == nullptr);
    OE_TEST(oe_attest_acquire_registry(role) == OE_OK);
    OE_TEST(oe_attest_begin_shutdown(role) == OE_BUSY);
    oe_attest_release_plugin(role);
    OE_TEST(oe_attest_begin_shutdown(role) == OE_OK);
    for (auto& plugin : plugins)
        OE_TEST(oe_attest_unregister_plugin(role, &list, &plugin) == OE_OK);
    OE_TEST(list == nullptr);
    oe_attest_end_shutdown();
}

struct TestVerifier
{
    oe_verifier_t plugin = {};
    Gate gate;
    oe_result_t result = OE_OK;
    bool freed_claims = false;
};

static TestVerifier* _verifier_test;

static oe_result_t _verify(
    oe_verifier_t* plugin,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const oe_policy_t*,
    size_t,
    oe_claim_t** claims,
    size_t* claims_length)
{
    auto* test = _verifier_test;
    OE_TEST(plugin == &test->plugin);
    test->gate.pause();
    if (claims)
    {
        *claims = nullptr;
        *claims_length = 0;
    }
    return test->result;
}

static oe_result_t _free_claims(oe_verifier_t* plugin, oe_claim_t*, size_t)
{
    auto* test = _verifier_test;
    OE_TEST(plugin == &test->plugin);
    OE_TEST(oe_unregister_verifier_plugin(plugin) == OE_BUSY);
    test->freed_claims = true;
    return OE_OK;
}

static void _test_verifier(oe_result_t callback_result, bool invalid_claims)
{
    OE_TEST(oe_verifier_initialize() == OE_OK);
    TestVerifier test;
    _verifier_test = &test;
    test.plugin.base.format_id.b[0] = 0xfe;
    test.plugin.base.on_register = _on_register;
    test.plugin.base.on_unregister = _on_unregister;
    test.plugin.verify_evidence = _verify;
    test.plugin.free_claims = _free_claims;
    test.result = callback_result;
    OE_TEST(oe_register_verifier_plugin(&test.plugin, nullptr, 0) == OE_OK);
    oe_verifier_t peer = test.plugin;
    peer.base.format_id.b[0] = 0xfd;
    OE_TEST(oe_register_verifier_plugin(&peer, nullptr, 0) == OE_OK);

    oe_uuid_t* before = nullptr;
    size_t before_count = 0;
    OE_TEST(oe_verifier_get_formats(&before, &before_count) == OE_OK);
    oe_result_t result = OE_UNEXPECTED;
    std::thread dispatch([&] {
        const uint8_t evidence = 0;
        oe_claim_t* claims = nullptr;
        size_t claims_length = 0;
        result = oe_verify_evidence(
            &test.plugin.base.format_id,
            &evidence,
            sizeof(evidence),
            nullptr,
            0,
            nullptr,
            0,
            invalid_claims ? &claims : nullptr,
            invalid_claims ? &claims_length : nullptr);
    });

    test.gate.wait();
    OE_TEST(oe_verifier_shutdown() == OE_BUSY);
    OE_TEST(oe_unregister_verifier_plugin(&test.plugin) == OE_BUSY);
    OE_TEST(oe_unregister_verifier_plugin(&peer) == OE_BUSY);
    OE_TEST(oe_verifier_initialize() == OE_OK);
    oe_uuid_t* after = nullptr;
    size_t after_count = 0;
    OE_TEST(oe_verifier_get_formats(&after, &after_count) == OE_OK);
    OE_TEST(before_count == after_count);
    OE_TEST(memcmp(before, after, before_count * sizeof(*before)) == 0);
    OE_TEST(oe_verifier_free_formats(before) == OE_OK);
    OE_TEST(oe_verifier_free_formats(after) == OE_OK);

    test.gate.release();
    dispatch.join();
    OE_TEST(
        result == (invalid_claims ? OE_CONSTRAINT_FAILED : callback_result));
    OE_TEST(test.freed_claims == invalid_claims);
    OE_TEST(oe_unregister_verifier_plugin(&peer) == OE_OK);
    OE_TEST(oe_unregister_verifier_plugin(&test.plugin) == OE_OK);
    OE_TEST(oe_verifier_shutdown() == OE_OK);
    OE_TEST(oe_verifier_initialize() == OE_OK);
    OE_TEST(oe_verifier_shutdown() == OE_OK);
    _verifier_test = nullptr;
}

int main(int argc, const char* argv[])
{
    OE_TEST(argc == 2);
    if (strcmp(argv[1], "--host-only") == 0)
    {
        _test_registry(OE_ATTEST_ROLE_ATTESTER);
        _test_registry(OE_ATTEST_ROLE_VERIFIER);
        _test_verifier(OE_OK, false);
        _test_verifier(OE_FAILURE, false);
        _test_verifier(OE_OK, true);
        puts("Plugin lifetime host tests passed.");
        return 0;
    }

    oe_enclave_t* enclave = nullptr;
    OE_TEST(
        oe_create_plugin_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_SGX,
            oe_get_create_flags(),
            nullptr,
            0,
            &enclave) == OE_OK);
    std::thread report(
        [&] { OE_TEST(test_report_lifetime(enclave) == OE_OK); });
    _report_gate.wait();
    OE_TEST(test_attester_shutdown_busy(enclave) == OE_OK);
    _report_gate.release();
    report.join();
    OE_TEST(test_attester_shutdown_after_release(enclave) == OE_OK);
    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    puts("Plugin lifetime enclave tests passed.");
    return 0;
}
