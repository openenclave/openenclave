#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void __stack_chk_fail(void);

void __stack_chk_fail(void)
{
    puts("*** Stack smashing detected!");
    abort();
}
