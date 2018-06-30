#include <openenclave/internal/corelibc/stdio.h>

FILE* const stdin = ((FILE*)0x1000000000000001);
FILE* const stdout = ((FILE*)0x1000000000000002);
FILE* const stderr = ((FILE*)0x1000000000000003);
