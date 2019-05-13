// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "all_t.h"

// Assert that the struct is copied by value, such that `s.ptr` is the
// address of `data[]` in the host (also passed via `ptr`).
void deepcopy_value(struct MyStruct s, uint64_t* ptr)
{
    OE_TEST(s.count == 7);
    OE_TEST(s.size == 64);
    OE_TEST(s.ptr == ptr);
    OE_TEST(oe_is_outside_enclave(s.ptr, sizeof(uint64_t)));
}
