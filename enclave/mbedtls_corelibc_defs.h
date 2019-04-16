// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/stdio.h>

/* Only map CHAR_BIT out of limits.h to scope potential standard definition
 * name conflicts in enclave sources.
 */
#if !defined(CHAR_BIT)
#define CHAR_BIT OE_CHAR_BIT
#endif

/* Define FILE, which is used by an mbed TLS header. */
#if !defined(FILE)
#define FILE OE_FILE
#endif

/* Custom redefine of the pthread_mutex_t to oe_pthread_t.
 * This uses a define rather than the typedef in pthread.h so that its use
 * can be scoped to the mbedtls headers and subsequently undefined afterwards.
 */
#if !defined(pthread_mutex_t)
#define pthread_mutex_t oe_pthread_mutex_t
#endif
