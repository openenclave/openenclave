// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

OE_EXTERNC_BEGIN
void* test_host_alloc_for_call_host(size_t size);
void test_host_free_for_call_host(void* p);
OE_EXTERNC_END

size_t GetAllocationCount();
size_t GetAllocationBytes();
void Exit();
