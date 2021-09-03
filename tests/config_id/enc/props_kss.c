// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX2(
    1, /* ProductID */
    1, /* SecurityVersion */
    ({0x47,
      0x18,
      0x38,
      0x23,
      0x25,
      0x74,
      0x4b,
      0xfd,
      0xb4,
      0x11,
      0x99,
      0xed,
      0x17,
      0x7d,
      0x3e,
      0x43}), /* ExtendedProductID */
    ({0x27,
      0x68,
      0xc7,
      0x20,
      0x1e,
      0x28,
      0x11,
      0xeb,
      0xad,
      0xc1,
      0x02,
      0x42,
      0xac,
      0x12,
      0x00,
      0x02}), /* FamilyID */
    true,     /* Debug */
    false,    /* CapturePFGPExceptions */
    true,     /* RequireKSS */
    false,    /* CreateZeroBaseEnclave */
    0,        /* StartAddress */
    1024,     /* NumHeapPages */
    1024,     /* NumStackPages */
    1);       /* NumTCS */
