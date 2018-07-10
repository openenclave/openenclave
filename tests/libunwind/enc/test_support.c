#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

extern uint32_t process_id;

int setrlimit(int resource, int *rlim)
{
    return 0;
}

pid_t getpid(void)
{

    return process_id;
}
