/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

/* Override the normal tcps.h file with this one, so that this
 * will be used by code generated from oeinternal.edl.  This
 * would not be needed if oeedger8r had an option to do this
 * for us for internal APIs.
 */
#include "../../../include/tcps.h"
#define oe_call_enclave_function oe_call_internal_enclave_function
#define oe_create_enclave oe_create_internal_enclave
