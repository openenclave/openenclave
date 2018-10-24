// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file exists so that each test has its own copy of
// `__TEST__NAME`, that way the enclave can print the name as it loads
// and runs the test.
const char* __TEST__NAME = __TEST__;
#include __TEST__
