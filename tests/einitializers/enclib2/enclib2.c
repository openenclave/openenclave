// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/initializers.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

static void enclib2_phase1()
{
    // phase1 depends on enclave app's initializers (if availabe)
    // as well as enclibc1's phase1 (if available).
    oe_call_initializer_group("app-initializers");
    oe_call_initializer_group("enclib1-phase1");
    printf("enclib2_phase1 called.\n");
}

static void enclib2_phase2()
{
    // enclib2 depends on enclib1-phase2 (if available).
    // Call enclib1-phase2 initializers.
    oe_call_initializer_group("enclib1-phase2");
    printf("enclib2_phase2 called.\n");
}

OE_REGISTER_ENCLAVE_INITIALIZER("enclib2-phase1", enclib2_phase1);
OE_REGISTER_ENCLAVE_INITIALIZER("enclib2-phase2", enclib2_phase2);

// This symbol acts as the handle for the library in linker command lines
// to ensure that this file and all of it's dependencies are pulled in.
void* enclib2;
