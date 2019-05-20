// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_LIBC_SUPPRESS_DEPRECATIONS
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#if defined(_MSC_VER)
#define OE_NEED_STD_NAMES
#include <windows.h>
static void sleep(int secs)
{
    Sleep(secs * 1000);
}
typedef HANDLE pthread_t;
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include "openenclave/corelibc/signal.h"
#include "signal_test_u.h"

#define SERVER_PORT "12345"

int received_signum = -1;

oe_result_t oe_posix_signal_notify_ecall(
    oe_enclave_t* enclave,
    int* _retval,
    int signum);

void sigusr2_handler(int signum)
{
    // Doens't do anything. We expect sigpipe from the signal pipe
    printf("host received signal %d\n", signum);
    received_signum = signum;
}

oe_enclave_t* client_enclave = NULL;
void* host_signal_thread(void* arg)
{
    int* done = (int*)arg;
    int ret = 0;

    while (!*done)
    {
        (void)oe_posix_signal_notify_ecall(client_enclave, &ret, OE_SIGUSR1);
        sleep(3);
    };

    printf("exit from signal thread\n");
    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    pthread_t signal_thread_id = 0;
    int ret = 0;
    char test_data_rtn[1024] = {0};
    size_t test_data_len = 1024;
    int done = 0;
    bool sigout = true;

    if (argc == 3)
    {
        if (strcmp("nosignal-out", argv[2]) == 0)
        {
            sigout = false;
        }
        else
        {
            fprintf(stderr, "Usage: %s ENCLAVE_PATH [nosignal-out]\n", argv[0]);
            return 1;
        }
    }
    else if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }
#if defined(_WIN32)
    signal_thread_id = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)host_signal_thread, (void*)(&done), 0, NULL);
    OE_TEST(signal_thread_id != INVALID_HANDLE_VALUE);
#else
    struct sigaction action = {{sigusr2_handler}};
    sigaction(OE_SIGUSR2, &action, NULL);

    // host signal to enclave client
    // This is only applicable to linux as windows hardly has any signal facility
    OE_TEST(
        pthread_create(
            &signal_thread_id, NULL, host_signal_thread, (void*)&done) == 0);

    sleep(3); // Give the signal time to launch
#endif
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_signal_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &client_enclave);

    OE_TEST(result == OE_OK);

    OE_TEST(ecall_device_init(client_enclave, &ret) == OE_OK);

    test_data_len = 1024;
    OE_TEST(
        ecall_signal_in_test(
            client_enclave, &ret, test_data_len, test_data_rtn) == OE_OK);

    sleep(5);

    printf(
        "signal to enclave: host received from signal handler: %s\n",
        test_data_rtn);
    done = 2;

#if defined(__linux__)
    int numtries = 10;
    if (sigout)
    {
        received_signum = -1;
        pid_t pid = getpid();
        OE_TEST(
            ecall_signal_out_test(client_enclave, &ret, (uint64_t)pid) ==
            OE_OK);

        while (received_signum == -1 && numtries > 0)
        {
            printf("waiting for signal\n");
            sleep(1);
            numtries--;
        }

        OE_TEST(received_signum == SIGUSR2);
    }

    pthread_join(signal_thread_id, NULL);
#else
   ret = WaitForSingleObject(signal_thread_id, INFINITE);
#endif

    OE_TEST(oe_terminate_enclave(client_enclave) == OE_OK);

    printf("=== passed all tests (signal_test)\n");

    return 0;
}
