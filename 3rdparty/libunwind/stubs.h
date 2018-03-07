// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef __OE_LIBUNWIND_STUBS_H
#define __OE_LIBUNWIND_STUBS_H

#define mmap __libunwind_mmap

#define munmap __libunwind_munmap

#define msync __libunwind_msync

#define mincore __libunwind_mincore

#endif /* __OE_LIBUNWIND_STUBS_H */
