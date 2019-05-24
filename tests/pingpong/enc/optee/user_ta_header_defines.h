/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 0a6cbbd3-160a-4c86-9d9d-c9cf1956be16 */           \
        0x0a6cbbd3, 0x160a, 0x4c86,                        \
        {                                                  \
            0x9d, 0x9d, 0xc9, 0xcf, 0x19, 0x56, 0xbe, 0x16 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                     \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "pingpong test TA"}, \
    {                                                                    \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)        \
        {                                                                \
            0x0010                                                       \
        }                                                                \
    }
