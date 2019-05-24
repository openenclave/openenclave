/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 688ab13f-5bc0-40af-8dc6-01d007fd2210 */           \
        0x688ab13f, 0x5bc0, 0x40af,                        \
        {                                                  \
            0x8d, 0xc6, 0x01, 0xd0, 0x07, 0xfd, 0x22, 0x10 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                         \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "create-rapid test TA"}, \
    {                                                                        \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)            \
        {                                                                    \
            0x0010                                                           \
        }                                                                    \
    }
