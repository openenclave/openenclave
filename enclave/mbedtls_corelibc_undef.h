// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* This header should not generally be used in the scope of
 * OE_NEED_STDC_NAMES as it could undefine some names.
 * Consider if any definitions provided should be special
 * cased in mbedtls_corelibc_defs.h instead.
 */
#if defined(OE_NEED_STDC_NAMES)
#error "mbedtls_corelibc_undef.h should not be used with OE_NEED_STDC_NAMES"
#endif

/* Remove the CHAR_BIT mappings provided by limits.h */
#if defined(CHAR_BIT)
#undef CHAR_BIT
#endif

/* Remove the FILE definition, which was already used by an mbed TLS header. */
#if defined(FILE)
#undef FILE
#endif

/* Undefine the custom pthread_mutex_t redefine */
#if defined(pthread_mutex_t)
#undef pthread_mutex_t
#endif
