// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef __OE_LIBCXXRT_STUBS_H
#define __OE_LIBCXXRT_STUBS_H

#define dladdr __libcxxrt_dladdr

#define printf __libcxxrt_printf

#define fprintf __libcxxrt_fprintf

#define sched_yield __libcxxrt_sched_yield

#define calloc __oe_calloc

#define malloc __oe_malloc

#define realloc __oe_realloc

#define free __oe_free

#define memalign __oe_memalign

#define posix_memalign __oe_posix_memalign

#endif /* __OE_LIBCXXRT_STUBS_H */
