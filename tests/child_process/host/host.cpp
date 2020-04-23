// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "child_process_u.h"

#define ECALL_IN_CHILD_PROCESS 0
#define DESTROY_IN_CHILD_PROCESS 1
#define CREATE_IN_CHILD_PROCESS 2

bool multi_process_flag = true;

void stay_ocall(void)
{
    // sleep for 5 seconds.
    sleep(5);
}

int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TEST_NUMBER\n", argv[0]);
        exit(1);
    }
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    int fpipe[2];
    int64_t process_result = pipe(fpipe);
    if (process_result != 0)
    {
        fprintf(stderr, "Failed to create pipe\n");
        exit(1);
    }

    int pid;
    oe_result_t result, result_child_process;
    result = oe_create_child_process_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    pid = fork();
    switch (atoi(argv[2]))
    {
        case ECALL_IN_CHILD_PROCESS:
            if (pid == 0) // child process
            {
                close(fpipe[0]);
                fprintf(stdout, "child pid = %d\n", getpid());
                uint32_t magic = 2;
                result_child_process = get_magic_ecall(enclave, &magic);
                OE_TEST(result_child_process != OE_OK);
                OE_TEST(magic == 2);
                process_result =
                    write(fpipe[1], &result_child_process, sizeof(oe_result_t));
                process_result = close(fpipe[1]);
                _exit(EXIT_SUCCESS);
            }
            else if (pid > 0) // parent process
            {
                fprintf(stdout, "parent pid = %d\n", getpid());
                process_result = close(fpipe[1]);
                process_result = read(fpipe[0], &result, sizeof(oe_result_t));
                process_result = close(fpipe[0]);
                OE_TEST(result == OE_OK);
                oe_terminate_enclave(enclave);
                wait(NULL);
            }
            else
            {
                fprintf(stderr, "failed to create child process.\n");
                exit(1);
            }
            break;
        case DESTROY_IN_CHILD_PROCESS:
            if (pid == 0) // child process
            {
                result_child_process = oe_terminate_enclave(enclave);
                OE_TEST(result_child_process == OE_INVALID_PARAMETER);
            }
            else if (pid > 0) // parent process
            {
                uint32_t magic;
                result = get_magic_ecall(enclave, &magic);
                OE_TEST(result == OE_OK);
                OE_TEST(magic == 0x1234);
                oe_terminate_enclave(enclave);
                wait(NULL);
            }
            else
            {
                fprintf(stderr, "failed to create child process.\n");
                exit(1);
            }
            break;
        case CREATE_IN_CHILD_PROCESS:
            if (pid == 0) // child process
            {
                fprintf(stdout, "child pid = %d\n", getpid());
                oe_enclave_t* enclave_in_child_process = NULL;
                result = oe_create_child_process_enclave(
                    argv[1],
                    OE_ENCLAVE_TYPE_SGX,
                    flags,
                    NULL,
                    0,
                    &enclave_in_child_process);
                OE_TEST(result == OE_OK);
                oe_terminate_enclave(enclave_in_child_process);
                _exit(EXIT_SUCCESS);
            }
            else if (pid > 0) // parent process
            {
                fprintf(stdout, "parent pid = %d\n", getpid());
                oe_terminate_enclave(enclave);
                wait(NULL);
            }
            else
            {
                fprintf(stderr, "failed to create child process.\n");
                exit(1);
            }
            break;
        default:
            break;
    }
    // Clean up the enclave
    if (enclave)
        oe_terminate_enclave(enclave);

    return 0;
}
