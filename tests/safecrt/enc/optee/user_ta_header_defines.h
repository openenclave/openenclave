/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 91dc6667-7a33-4bbc-ab3e-ab4fca5215b7 */           \
        0x91dc6667, 0x7a33, 0x4bbc,                        \
        {                                                  \
            0xab, 0x3e, 0xab, 0x4f, 0xca, 0x52, 0x15, 0xb7 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                    \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "safecrt test TA"}, \
    {                                                                   \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)       \
        {                                                               \
            0x0010                                                      \
        }                                                               \
    }
