// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/pthreadhooks.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream> //std::cout
#include <vector>
#include <map>
#include "../args.h"
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

static std::vector<std::function<void*()>> _thread_functions;
static std::atomic_flag _lock = ATOMIC_FLAG_INIT;
static pthread_t _next_enc_thread_id = 0;
static std::map<pthread_t, pthread_t> _enclave_host_id_map;

static void _acquire_lock()
{
    while (_lock.test_and_set(std::memory_order_acquire))
        ;
}

static void _release_lock()
{
    _lock.clear(std::memory_order_release);
}

static int _pthread_create_hook(
    pthread_t* enc_thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    _acquire_lock();

    _thread_functions.push_back(
        [start_routine, arg]() { return start_routine(arg); });

    *enc_thread = ++_next_enc_thread_id;
    _release_lock();

    if (oe_call_host("host_create_pthread", NULL) != OE_OK)
        oe_abort();

    return 0;
}

static int _pthread_join_hook(pthread_t enc_thread, void** retval)
{
  std::map<pthread_t, pthread_t>::iterator it;
  
    // Check if valid thread_id has been passed
    if (enc_thread > _next_enc_thread_id)
    {
        std::cout << "(_pthread_join_hook)Invalid Thread ID " << enc_thread << std::endl;
        oe_abort();
    }

    //Get the host thread id and pass it to host for join
    it = _enclave_host_id_map.find(enc_thread);
    /* if (it == _enclave_host_id_map.end())
       oe_abort(); */
    
    my_pthread_args_t args;
    args.host_thread_id = it->second; //_enclave_host_id_map[enc_thread];
    args.ret = 0;
    std::cout << "_pthread_join_hook " << args.host_thread_id << std::endl;
    
    if (oe_call_host("host_join_pthread", &args) != OE_OK)
        oe_abort();

    return 0;
}

OE_ECALL void _EnclaveLaunchThread(void* args_)
{
  my_pthread_args_t* args = (my_pthread_args_t*)args_;
  std::cout << "Entering Enclave Launch thread----------hostid=" << args->host_thread_id << std::endl;
    
    std::function<void()> f;
    _acquire_lock();
    if (!_next_enc_thread_id)
      {
        std::cout << "(_EnclaveLaunchThread)Invalid Next Thread ID " << _next_enc_thread_id << std::endl;
        oe_abort();
      } 
    //Add the mapping of enc_thread_id to host_thread_id
    _enclave_host_id_map[_next_enc_thread_id-1] = args->host_thread_id;
    f = _thread_functions.back();
    _thread_functions.pop_back();
    _release_lock();
    f();
    printf("Exiting Enclave Launch thread---------\n");
}

OE_ECALL void _EnclaveJoinThread(void* args_)
{
  std::cout << "In _EnclaveJoinThread function\n";
  my_pthread_args_t* args = (my_pthread_args_t*)args_;

  if (args)
    {
      std::cout << "host thread id in _EnclaveJoinThread is " << args->host_thread_id << std::endl;;
      pthread_join(args->host_thread_id, NULL);
    }
  
  /* if (pthread_join(args->host_thread_id, &retVal) != 0)
    {
      std::cout << "(_EnclaveJoinThread)pthread_join failed for " << args->host_thread_id << std::endl;
      oe_abort();
      } */
}

OE_ECALL void Test(Args* args)
{
    static oe_pthread_hooks_t _hooks = {.create = _pthread_create_hook,
                                        .join = _pthread_join_hook};
    oe_register_pthread_hooks(&_hooks);

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
    4);   /* TCSCount */
