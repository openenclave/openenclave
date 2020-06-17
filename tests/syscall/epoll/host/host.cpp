// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <cstdio>
#include <thread>
#include "epoll_u.h"

using namespace std;

int main(int argc, const char* argv[])
{
    oe_result_t r;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    oe_enclave_t* enclave;
    r = oe_create_epoll_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    // Test concurrent use of epoll

    set_up(enclave);

    thread wait_thread(
        [enclave] { OE_TEST(wait_for_events(enclave) == OE_OK); });
    this_thread::sleep_for(100ms); // give wait_thread time to initialize

    for (int i = 0; i < 100; ++i)
    {
        OE_TEST(trigger_and_add_event(enclave) == OE_OK);
        OE_TEST(trigger_and_delete_event(enclave) == OE_OK);
    }

    cancel_wait(enclave);
    wait_thread.join();
    tear_down(enclave);

    // Test closing file descriptors without deleting them from the epoll
    // instance
    OE_TEST(test_close_without_delete(enclave) == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (epoll)\n");
    fflush(stdout);

    return 0;
}
