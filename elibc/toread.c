#include <stdio.h>
#include <assert.h>

void __toread_needs_stdio_exit(void);
void __stdio_exit_needed(void);

void __stdio_exit_needed(void)
{
    assert("__stdio_exit_needed() called" == NULL);
}

#include "../3rdparty/musl/musl/src/stdio/__toread.c"
