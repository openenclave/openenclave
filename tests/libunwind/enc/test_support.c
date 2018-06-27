#include <unistd.h>
#include <stdio.h>
#include <stdint.h>


extern uint32_t process_id;
pid_t getpid(void)
{

    return process_id;
}
