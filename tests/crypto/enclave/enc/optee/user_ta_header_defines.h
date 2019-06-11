/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* f0be7db0-ce7c-4dc4-b8c8-b161f4216225 */           \
        0xf0be7db0, 0xce7c, 0x4dc4,                        \
        {                                                  \
            0xb8, 0xc8, 0xb1, 0x61, 0xf4, 0x21, 0x62, 0x25 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (24 * 1024)      /* 24 KB */
#define TA_DATA_SIZE (2 * 1024 * 1024) /* 2 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                   \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "crypto test TA"}, \
    {                                                                  \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)      \
        {                                                              \
            0x0010                                                     \
        }                                                              \
    }
