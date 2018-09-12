// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/tests.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include "../host/args.h"
#include "../host/ocalls.h"

extern const char* __test__;

extern "C" int main(int argc, const char* argv[]);

extern "C" void _exit(int status)
{
    oe_call_host("ocall_exit", (void*)(long)status);
    abort();
}

extern "C" void _Exit(int status)
{
    _exit(status);
    abort();
}

extern "C" void exit(int status)
{
    _exit(status);
    abort();
}

typedef void (*Handler)(int signal);

Handler signal(int signal, Handler)
{
    /* Ignore! */
    return NULL;
}

extern "C" int close(int fd)
{
    OE_TEST("close() panic" == NULL);
    return 0;
}

static stack<func_ptr> enc_stack;

/* pthread function prototypes
int pthread_create(pthread_t *__restrict, const pthread_attr_t *__restrict, void *(*)(void *), void *__restrict);
int pthread_detach(pthread_t);
_Noreturn void pthread_exit(void *);
int pthread_join(pthread_t, void **);
*/

pthread_create(pthread_t* thread, const pthread_attr_t* attr,
	       void* (*enc_func_ptr)(void*), void* arg)
{
  enc_stack(enc_func_ptr);
  //Call host to create thread
  my_pthread_create_ocall(thread, attr, enc_func_ptr, arg);
}

OE_ECALL void EncStartThread()
{
  ptr p = enc_stack.pop_and_remove();
  p(); //Invoke the function 
  
}

OE_ECALL void Test(Args* args)
{
    extern const char* __TEST__NAME;
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__NAME);
        static const char* argv[] = {
            "test", NULL,
        };
        static int argc = sizeof(argv) / sizeof(argv[0]);
        args->ret = main(argc, argv);
        args->test = oe_host_strndup(__TEST__NAME, OE_SIZE_MAX);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    8192, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
