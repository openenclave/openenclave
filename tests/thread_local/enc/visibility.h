
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _VISIBILITY_SPEC_H
#define _VISIBILITY_SPEC_H

#ifdef EXPORT_THREAD_LOCALS
#define VISIBILITY_SPEC __attribute__((visibility("default")))
#else
#define VISIBILITY_SPEC __attribute__((visibility("hidden")))
#endif

#endif // _VISIBILITY_SPEC_H
