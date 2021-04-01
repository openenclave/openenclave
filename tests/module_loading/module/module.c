// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

extern int is_module_init;

void notify_module_done_wrapper();

__attribute__((constructor)) void init_module()
{
    is_module_init = 1;
}

__attribute__((destructor)) void fini_module()
{
    notify_module_done_wrapper();
}

int square(int a)
{
    return a * a;
}

int k = 500;

int add_with_constant(int a, int b)
{
    return a + b + k;
}
