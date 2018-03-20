// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _rwlock_tests_h
#define _rwlock_tests_h

const size_t RWLOCK_TEST_ITERS = 2000;

// Microseconds to sleep after obtaining a read or writer lock.
const size_t sleep_utime = 10;

// Number of reader threads. Also see NUM_THREADS in rwlocks_test_host.cpp.
const size_t NUM_READER_THREADS = 4;

#endif /* _rwlock_tests_h */
