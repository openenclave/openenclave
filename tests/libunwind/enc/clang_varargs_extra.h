// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Provide forward declarations of functions in libunwind test suite
// so that we can provide clang-specific annotations without modifying 3rdparty/
void a(int, ...) __attribute__((optnone));
void b(void) __attribute__((optnone));
void c(void) __attribute__((optnone));
