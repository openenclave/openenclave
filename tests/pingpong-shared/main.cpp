// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

extern "C" __attribute__((section(".ecall"))) void __ping(void* args);

int main()
{
    __ping(0);
    return 0;
}
