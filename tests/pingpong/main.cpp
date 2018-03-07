// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

extern "C" __attribute__((section(".ecall"))) void __Ping(void* args);

int main()
{
    __Ping(0);
    return 0;
}
