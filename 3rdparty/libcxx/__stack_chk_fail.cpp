#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

extern "C" void __stack_chk_fail(void)
{
    assert("__stack_chk_fail()" == NULL);
    abort();
}
