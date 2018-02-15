#include <openenclave/bits/error.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>

static const char* _programName = "";

void OE_SetProgramName(const char* name)
{
    _programName = name;
}

OE_PRINTF_FORMAT(3, 4)
void __OE_PutErr(const char* file, unsigned int line, const char* format, ...)
{
    fprintf(stderr, "%s: %s(%u): error: ", _programName, file, line);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n");
    exit(1);
}
