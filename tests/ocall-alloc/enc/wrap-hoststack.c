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

#define oe_host_alloc_for_call_host MyHostAllocForCallHost
#define oe_host_free_for_call_host MyHostFreeForCallHost
#define __cxa_atexit My__cxa_atexit
#define oe_host_malloc MyHostMalloc
#define oe_host_free MyHostFree

#include "../../../enclave/core/hoststack.c"
