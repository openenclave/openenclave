// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Published headers under the include directory.
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/attestation.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/edl/syscall_types.h>
#include <openenclave/bits/exception.h>
#include <openenclave/bits/fs.h>
#include <openenclave/bits/module.h>
#include <openenclave/bits/properties.h> // Implicitly test sgxproperties.h and opteeproperties.h.
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/plugin.h>
#if __x86_64__ || _M_X64
#include <openenclave/bits/sgx/epid.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#endif
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/defs.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/wchar.h>
#include <openenclave/edger8r/common.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

// Oeedger8r-generated headers.
#include <openenclave/bits/asym_keys.h>
#include <openenclave/bits/time.h>

int enc_c99_compliant()
{
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    256,  /* NumHeapPages */
    256,  /* NumStackPages */
    2);   /* NumTCS */

#define TA_UUID                                            \
    { /* b843807a-e05c-423c-bcfb-1062cadb482f */           \
        0xb843807a, 0xe05c, 0x423c,                        \
        {                                                  \
            0xbc, 0xfb, 0x10, 0x62, 0xca, 0xdb, 0x48, 0x2f \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "C99-compliant test")
