#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

__NORETURN void __assert_fail(
    const char *expr,
    const char *file,
    unsigned int line,
    const char *function)
{
    char buf[1024];

    snprintf(buf, sizeof(buf), "Assertion failed: %s (%s: %s: %d)\n", 
        expr, file, function, line);
    puts(buf);
    abort();
}
