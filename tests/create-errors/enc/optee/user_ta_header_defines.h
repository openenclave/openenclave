/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 1083bbac-751e-4d26-ada6-c254bbfbe653 */           \
        0x1083bbac, 0x751e, 0x4d26,                        \
        {                                                  \
            0xad, 0xa6, 0xc2, 0x54, 0xbb, 0xfb, 0xe6, 0x53 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                          \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "create-errors test TA"}, \
    {                                                                         \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)             \
        {                                                                     \
            0x0010                                                            \
        }                                                                     \
    }
