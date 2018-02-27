#include <assert.h>
#include <sched.h>
#include <stdio.h>

int sched_yield(void)
{
    assert("sched_yield(): panic" == NULL);
    return -1;
}
