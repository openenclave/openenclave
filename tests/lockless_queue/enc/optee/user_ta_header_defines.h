/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* eb99d409-3d52-439c-b374-87f664136434 */           \
        0xeb99d409, 0x3d52, 0x439c,                        \
        {                                                  \
            0xb3, 0x74, 0x87, 0xf6, 0x64, 0x13, 0x64, 0x34 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                    \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "hexdump test TA"}, \
    {                                                                   \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)       \
        {                                                               \
            0x0010                                                      \
        }                                                               \
    }
