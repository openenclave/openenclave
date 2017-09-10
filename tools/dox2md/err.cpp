#include <cstdio>
#include <cstdarg>

extern const char* arg0;

__attribute__((format(printf, 1, 2)))
void err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", arg0);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}
