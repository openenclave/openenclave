/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID { /* 3156152a-19d1-423c-96ea-5adf5675798f */ \
    0x3156152a, \
    0x19d1, \
    0x423c, \
    {0x96, 0xea, 0x5a, 0xdf, 0x56, 0x75, 0x79, 0x8f} \
  }

#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE               (24 * 1024)        /* 24 KB */
#define TA_DATA_SIZE                (1 * 1024 * 1024)  /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "Open Enclave Test TA" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }
