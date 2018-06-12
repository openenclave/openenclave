// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
   Wrapper for OE_HostAllocForCallHost() for whitebox-testing. Wrapped:

   + OE_HostAllocForCallHost
   + OE_HostFreeForCallHost
   + __cxa_atexit
   + OE_HostMalloc
   + OE_HostFree

 */

#define OE_HostAllocForCallHost MyOE_HostAllocForCallHost
#define OE_HostFreeForCallHost MyOE_HostFreeForCallHost
#define __cxa_atexit My__cxa_atexit
#define OE_HostMalloc MyOE_HostMalloc
#define OE_HostFree MyOE_HostFree

#include "../../../enclave/core/hoststack.c"
