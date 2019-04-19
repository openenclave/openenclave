// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* Check that the syntax of the standard C declarations. */
#define OE_NEED_STDC_NAMES
#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/assert.h>
#include <openenclave/corelibc/ctype.h>
#include <openenclave/corelibc/dirent.h>
#include <openenclave/corelibc/endian.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/corelibc/inttypes.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/corelibc/poll.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/sched.h>
#include <openenclave/corelibc/setjmp.h>
#include <openenclave/corelibc/signal.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/stdbool.h>
#include <openenclave/corelibc/stddef.h>
#include <openenclave/corelibc/stdint.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/corelibc/sys/eventfd.h>
#include <openenclave/corelibc/sys/ioctl.h>
#include <openenclave/corelibc/sys/mount.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/corelibc/sys/select.h>
#include <openenclave/corelibc/sys/signal.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/corelibc/sys/syscall.h>
#include <openenclave/corelibc/sys/time.h>
#include <openenclave/corelibc/sys/types.h>
#include <openenclave/corelibc/sys/uio.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/corelibc/time.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/corelibc/wchar.h>
