// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _CONTRACT_H
#define _CONTRACT_H

#define ENCLAVE_PAGE_SIZE 4096

// OSSA must be allocated immediately after the TCS page.
#define OSSA_FROM_TCS PAGE_SIZE

// Enclave must have at least 1 SSA by default
#define DEFAULT_SSA_FRAME_SIZE 1

// GS register must point to a structure that has an uint64_t ssa_frame_size
// member at the following offset.
#define GS_SSA_FRAME_SIZE_OFFSET 0x38

#endif // _CONTRACT_H
