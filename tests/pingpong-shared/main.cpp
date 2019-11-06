// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

extern "C" __attribute__((section(".ecall"))) void __ping(void* args);

int main()
{
    __ping(0);
    return 0;
}
