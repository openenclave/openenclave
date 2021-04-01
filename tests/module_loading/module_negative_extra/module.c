// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

__attribute__((constructor)) void init_module_extra()
{
}

__attribute__((destructor)) void fini_module_extra()
{
}

int foo(int a)
{
    return a;
}
