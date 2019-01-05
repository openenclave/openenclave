// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/initializers.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

static void enclib1_phase1()
{
    // phase 1 depends on enclave app initializers (if available)
    oe_call_initializer_group("app-initializers");
    printf("enclib1_phase1 called.\n");
}

static void enclib1_phase2()
{
    // phase2 depends on enclib2's phase1 (if available).
    oe_call_initializer_group("enclib2-phase1");
    printf("enclib1_phase2 called.\n");
}

OE_REGISTER_ENCLAVE_INITIALIZER("enclib1-phase1", enclib1_phase1);
OE_REGISTER_ENCLAVE_INITIALIZER("enclib1-phase2", enclib1_phase2);

// This symbol acts as the handle for the library in linker lines
// to ensure that this file and any of it's dependencies are pulled in.
void* enclib1;
