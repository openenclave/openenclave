// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file evidence.h
 *
 * This file defines object identities for evidence generation and
 * verification.
 *
 */
#ifndef _OE_INTERNAL_EVIDENCE_H
#define _OE_INTERNAL_EVIDENCE_H

#include "defs.h"
#include "types.h"

OE_EXTERNC_BEGIN

// ISO(1).ANSI(2).USA(840).Microsoft(113556).ACC(10).Classes(1).Subclass(2)
#define X509_OID_FOR_OE_EVIDENCE_EXT                         \
    {                                                        \
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x0A, 0x01, 0x02 \
    }
#define X509_OID_FOR_OE_EVIDENCE_STRING "1.2.840.113556.10.1.2"

#define X509_OID_FOR_NEW_OE_EVIDENCE_EXT                     \
    {                                                        \
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x69, 0x02 \
    }
#define X509_OID_FOR_NEW_OE_EVIDENCE_STRING "1.3.6.1.4.1.311.105.2"

OE_EXTERNC_END

#endif /* _OE_INTERNAL_EVIDENCE_H */
