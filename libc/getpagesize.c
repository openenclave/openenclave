#define _GNU_SOURCE
#include <unistd.h>

#define PAGE_SIZE 4096

int getpagesize(void)
{
    return PAGE_SIZE;
}
