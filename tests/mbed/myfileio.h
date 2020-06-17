// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef TEST_MBED_MYFILEIO_H
#define TEST_MBED_MYFILEIO_H

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#include <process.h>
typedef unsigned mode_t;
#else
#include <sys/uio.h>
#include <unistd.h>
#endif

#endif /* TEST_MBED_MYFILEIO_H */
