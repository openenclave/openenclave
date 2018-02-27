#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void __assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* function)
{
    char buf[1024];

    snprintf(
        buf,
        sizeof(buf),
        "Assertion failed: %s (%s: %s: %d)\n",
        expr,
        file,
        function,
        line);
    puts(buf);
    abort();
}
