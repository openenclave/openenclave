extern void oe_call_atexit_functions(void);

void ecall_InitializeStdio(void)
{

}

void _oe_entry(void)
{
    void (**fn)(void);

    extern void (*__init_array_start)(void);
    extern void (*__init_array_end)(void);

    for (fn = &__init_array_start; fn < &__init_array_end; fn++)
    {
        (*fn)();
    }
}

void _oe_exit(void)
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
