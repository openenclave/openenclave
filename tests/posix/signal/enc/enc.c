/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <openenclave/internal/time.h>

// enclave.h must come before socket.h
#include <openenclave/corelibc/signal.h>
#include <openenclave/internal/tests.h>

#include <assert.h>
#include <signal_test_t.h>
#include <stdio.h>
#include <string.h>

static char buff[1024] = {0};
void print_signal_success(int signum)
{
    sprintf(buff, "Received signal %d\n", signum);
    printf("Received signal %d\n", signum);
}

int ecall_device_init()
{
    OE_TEST(oe_load_module_posix() == OE_OK);
    OE_TEST(oe_load_module_hostfs() == OE_OK);

    oe_signal(OE_SIGUSR1, print_signal_success);
    return 0;
}

/* This client connects to an echo server, sends a text message,
 * and outputs the text reply.
 */
int ecall_signal_in_test(size_t buff_len, char* recv_buff)
{
    size_t n = 0;
    printf("--------------- receive signal -------------\n");

    OE_UNUSED(buff_len);

    do
    {
        oe_sleep_msec(3000);
        n = strlen(buff);
        if (n > 0)
        {
            memcpy(recv_buff, buff, n);
            break;
        }
    } while (n == 0);

    printf("--------------- signal  done -------------\n");
    return OE_OK;
}

int ecall_signal_out_test(uint64_t pid)
{
    printf("--------------- send signal -------------\n");
    memset(buff, 0, sizeof(buff));
    oe_kill((oe_pid_t)pid, OE_SIGUSR2);

    oe_sleep_msec(3000);

    printf("--------------- signal  done -------------\n");
    return OE_OK;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    16);  /* TCSCount */
