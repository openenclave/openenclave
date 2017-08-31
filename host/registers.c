#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <oeinternal/registers.h>

int OE_SetGSRegisterBase(const void *ptr)
{
    return syscall(__NR_arch_prctl, ARCH_SET_GS, ptr);
}

int OE_GetGSRegisterBase(const void **ptr)
{
    return syscall(__NR_arch_prctl, ARCH_GET_GS, ptr);
}
