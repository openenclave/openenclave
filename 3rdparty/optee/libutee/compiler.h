// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef COMPILER_H
#define COMPILER_H

#define __aligned(x) __attribute__((aligned(x)))
#define __printf(a, b) __attribute__((format(printf, a, b)))
#define __noreturn __attribute__((noreturn))

#endif /*COMPILER_H*/
