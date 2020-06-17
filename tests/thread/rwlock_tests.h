// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _rwlock_tests_h
#define _rwlock_tests_h

#include <openenclave/bits/types.h>

const size_t RWLOCK_TEST_ITERS = 2000;

// Microseconds to sleep after obtaining a read or writer lock.
const size_t sleep_utime = 10;

// Total number of threads. Half readers and half writers.
const size_t NUM_RW_TEST_THREADS = 8;

// Number of reader threads.
const size_t NUM_READER_THREADS = NUM_RW_TEST_THREADS / 2;

#endif /* _rwlock_tests_h */
