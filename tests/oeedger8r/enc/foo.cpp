// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "all_t.h"

// Implement functions in foo.edl.
// Only enc_foo1 is implemented since
// it is the only imported function.
void enc_foo1()
{
}

// No need to implement enc_foo2 since
// it is not imported
// void enc_foo2()
// {
// }
