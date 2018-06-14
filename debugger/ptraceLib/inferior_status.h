// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INFERIOR_STATUS_H_
#define _OE_INFERIOR_STATUS_H_

#include <pthread.h>

typedef enum _oe_inferior_flags {
    OE_INFERIOR_SINGLE_STEP = 0X1
} oe_inferior_flags_t;

int _oe_track_inferior(pid_t pid);

int _oe_untrack_inferior(pid_t pid);

int _oe_get_inferior_flags(pid_t pid, long* flags);

int _oe_set_inferior_flags(pid_t pid, long flags);

#endif