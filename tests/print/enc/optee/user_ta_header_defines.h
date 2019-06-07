/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 58f3e795-00c3-45e0-9435-3e6fcf734acc */           \
        0x58f3e795, 0x00c3, 0x45e0,                        \
        {                                                  \
            0x94, 0x35, 0x3e, 0x6f, 0xcf, 0x73, 0x4a, 0xcc \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                  \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "print test TA"}, \
    {                                                                 \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)     \
        {                                                             \
            0x0010                                                    \
        }                                                             \
    }
