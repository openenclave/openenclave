// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
   Wrapper for oe_host_alloc_for_call_host() for whitebox-testing. Wrapped:

   + oe_host_alloc_for_call_host
   + oe_host_free_for_call_host
   + __cxa_atexit
   + oe_host_malloc
   + oe_host_free

 */

#define oe_host_alloc_for_call_host test_host_alloc_for_call_host
#define oe_host_free_for_call_host test_host_free_for_call_host
#define oe_host_malloc test_host_malloc
#define oe_host_free test_host_free
#define oe_thread_key_create test_thread_key_create
#define oe_thread_setspecific test_thread_setspecific
#define oe_free_thread_buckets test_free_thread_buckets
#define __cxa_atexit test_cxa_atexit

#include "../../../enclave/core/hoststack.c"
