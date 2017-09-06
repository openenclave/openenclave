#include <sched.h>
#include <stdio.h>
#include <assert.h>

int sched_yield(void)
{
    assert("sched_yield(): panic" == NULL);
    return -1;
}
