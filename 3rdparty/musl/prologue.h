// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(__cplusplus)
# define OE_LIBC_EXTERN_C extern "C"
#else
# define OE_LIBC_EXTERN_C
#endif

#if defined(OE_LIBC_DEPRECATED)
# undef OE_LIBC_DEPRECATED
#endif

#if defined(OE_LIBC_SUPPRESS_DEPRECATIONS)
# define OE_LIBC_DEPRECATED OE_LIBC_EXTERN_C
#else
# define OE_LIBC_DEPRECATED OE_LIBC_EXTERN_C __attribute__((deprecated))
#endif
