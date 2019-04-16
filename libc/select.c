// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sys/select.h>
#include <openenclave/internal/defs.h>
#include <sys/select.h>

OE_STATIC_ASSERT(sizeof(oe_fd_set) == sizeof(fd_set));
OE_CHECK_FIELD(oe_fd_set, fd_set, fds_bits);
