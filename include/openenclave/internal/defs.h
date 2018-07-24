// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_DEFS_H
#define _OE_INTERNAL_DEFS_H

#define OE_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((weak, alias(#OLD)))

#endif /* _OE_INTERNAL_DEFS_H */
