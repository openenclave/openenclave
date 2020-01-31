// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "helpers.h"

int run_tests()
{
    extern int main(int argc, char** argv);
    return run_single_test(__TEST__, main);
}
