// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// These functions are needed by sqlite, and therefore must be defined
// in order to successfully link the enclave. However, these functions
// don't necessarily have to be implemented since the enclave may not
// use those parts of sqlite that depend on these functions.
//
// Development flow when using a library:
// 1) Build the enclave with the -Wl,--warn-unresolved-symbols option.
//    This will turn missing symbol errors into warnings.
// 2) Use the `objdump -t enclave | grep UND` command to list the missing
//    functions.
// 3) Perform tests by executing the enclave to figure out what functions
//    ought to be implemented. Missing functions most often result in a SEGV
//    in a call instruction.
// 4) Implement necessary missing functions and stub out the rest.
//    Remove the -Wl,--warn-unresolved-symbols option.

// The following functions need not be meaningfully implemented for this
// enclave's use of sqlite.

#include <dlfcn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))

void* dlopen_stub(const char* filename, int flag)
{
    abort();
    return NULL;
}
WEAK_ALIAS(dlopen_stub, dlopen);

char* dlerror_stub(void)
{
    abort();
    return NULL;
}
WEAK_ALIAS(dlerror_stub, dlerror);

void* dlsym_stub(void* handle, const char* symbol)
{
    abort();
    return NULL;
}
WEAK_ALIAS(dlsym_stub, dlsym);

int dlclose_stub(void* handle)
{
    abort();
    return -1;
}
WEAK_ALIAS(dlclose_stub, dlclose);

int fchmod_stub(int fd, mode_t mode)
{
    abort();
    return -1;
}
WEAK_ALIAS(fchmod_stub, fchmod);

int fchown_stub(int fd, uid_t owner, gid_t group)
{
    abort();
    return -1;
}
WEAK_ALIAS(fchown_stub, fchown);

int lstat_stub(const char* path, struct stat* buf)
{
    abort();
    return -1;
}
WEAK_ALIAS(lstat_stub, lstat);

void* mremap_stub(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    ... /* void *new_address */)
{
    abort();
    return NULL;
}
WEAK_ALIAS(mremap_stub, mremap);

int posix_fallocate_stub(int fd, off_t offset, off_t len)
{
    abort();
    return -1;
}
WEAK_ALIAS(posix_fallocate_stub, posix_fallocate);

ssize_t readlink_stub(const char* path, char* buf, size_t bufsiz)
{
    abort();
    return -1;
}
WEAK_ALIAS(readlink_stub, readlink);

int utimes_stub(const char* filename, const struct timeval times[2])
{
    abort();
    return -1;
}
WEAK_ALIAS(utimes_stub, utimes);
