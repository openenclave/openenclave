#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#if 0
void __cxa_pure_virtual(void);
void __cxa_pure_virtual(void)
{
    assert("__cxa_pure_virtual(): called pure virtual function");
}
#endif

const void *__dso_handle = NULL;

void __stack_chk_fail(void);
void __stack_chk_fail(void)
{
    printf_u("__stack_chk_fail(): stack smashing detected!\n");
    abort();
}

int __cxa_atexit(void (*func)(void *), void *arg, void *d);
int __cxa_atexit(void (*func)(void *), void *arg, void *d) 
{ 
    /* ATTN: Implement this! */
    printf_u("__cxa_atexit() called\n");
    return 0;
}

#if 1
oe_size_t fwrite(const void *ptr, oe_size_t size, oe_size_t nmemb, FILE *stream);
oe_size_t fwrite(const void *ptr, oe_size_t size, oe_size_t nmemb, FILE *stream)
{
    return 0;
}
#endif
