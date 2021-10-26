// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/debugmalloc.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/libc/init.h>
#include <openenclave/internal/malloc.h>
#include "core_t.h"

/* Forward declarartion for the symcrypt engine initializer */
int SC_OSSL_ENGINE_Initialize();

//
// start.S (the compilation unit containing the entry point) contains a
// reference to this function, which sets up a dependency chain from the
// object file containing the entry point to all symbols referenced in
// the array below (as well as symbols reachable from those symbols).
// This forces the collection of symbols to be included in the enclave
// image so that the linker will consider them when resolving symbols in
// subsequently linked libraries. The main purpose of this mechanism is
// to resolve reverse dependencies that liboecore has on liboeenclave.
//
const void* oe_link_enclave(void)
{
    static const void* symbols[] = {
        oe_verify_report_ecall,
        oe_get_public_key_by_policy_ecall,
        oe_get_public_key_ecall,
        /* Specify the following functions so that there are direct links from
         * enclave entry-point to these functions. This will cause the first
         * definitions of these functions to be picked up, which allow for
         * (weak) symbol overwritten */
        oe_allocator_malloc,
        oe_debug_malloc_tracking_start,
        oe_crypto_initialize,
        oe_libc_initialize,
        SC_OSSL_ENGINE_Initialize,
#if defined(OE_USE_DEBUG_MALLOC)
        oe_debug_malloc_check,
#endif /* defined(OE_USE_DEBUG_MALLOC) */
    };

    return symbols;
}
