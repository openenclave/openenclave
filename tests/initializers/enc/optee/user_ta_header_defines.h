/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 62f73b00-bdfe-4763-a06a-dc561a3a34d8 */           \
        0x62f73b00, 0xbdfe, 0x4763,                        \
        {                                                  \
            0xa0, 0x6a, 0xdc, 0x56, 0x1a, 0x3a, 0x34, 0xd8 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                         \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "initializers test TA"}, \
    {                                                                        \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)            \
        {                                                                    \
            0x0010                                                           \
        }                                                                    \
    }
