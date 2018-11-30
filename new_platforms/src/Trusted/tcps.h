/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

/* Override the normal tcps.h file with this one, so that this
 * will be used by code generated from oeinternal.edl.  This
 * would not be needed if oeedger8r had an option to do this
 * for us for internal APIs.
 */

#define __oe_ecalls_table       __oe_internal_ecalls_table
#define __oe_ecalls_table_size  __oe_internal_ecalls_table_size
#define _dummy_old_style_ecall_to_keep_loader_happy _internal_dummy_old_style_ecall_to_keep_loader_happy
