// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

void oe_call_init_functions(void)
{
    void (**fn)(void);

    extern void (*__init_array_start)(void);
    extern void (*__init_array_end)(void);

    for (fn = &__init_array_start; fn < &__init_array_end; fn++)
    {
        (*fn)();
    }
}

void oe_call_fini_functions(void)
{
    oe_call_atexit_functions();

    void (**fn)(void);

    extern void (*__fini_array_start)(void);
    extern void (*__fini_array_end)(void);

    for (fn = &__fini_array_start; fn < &__fini_array_end; fn++)
    {
        (*fn)();
    }
}
