#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void __stack_chk_fail(void);

void __stack_chk_fail(void)
{
    puts("*** Stack smashing detected!");
    abort();
}
