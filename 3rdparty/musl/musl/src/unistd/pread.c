#include <unistd.h>
#include "syscall.h"
#include "libc.h"

ssize_t pread(int fd, void *buf, size_t size, off_t ofs)
{
	return syscall_cp(SYS_pread, fd, buf, size, __SYSCALL_LL_PRW(ofs));
}

LFS64(pread);
