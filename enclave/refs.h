// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVE_REFS_H
#define _ENCLAVE_REFS_H

#include <openenclave/types.h>

/*
**==============================================================================
**
** These functions manage the a global reference counter used to keep a count
** of unreleased objects created this library. This number should be zero after ** all objects have been released.
**
**==============================================================================
*/

#ifndef NDEBUG
uint64_t OE_RefsGet();
void OE_RefsIncrement();
void OE_RefsDecrement();
#else
# define OE_RefsIncrement()
# define OE_RefsDecrement()
#endif

#endif /* _ENCLAVE_REFS_H */
