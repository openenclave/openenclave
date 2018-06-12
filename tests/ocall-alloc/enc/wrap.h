// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

OE_EXTERNC_BEGIN
void* MyHostAllocForCallHost(size_t size);
void MyOE_HostFreeForCallHost(void* p);
OE_EXTERNC_END

size_t MyGetAllocationCount();
size_t MyGetAllocationBytes();
void MyExit();
