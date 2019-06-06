/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 60814a64-61e9-4fd9-9159-e158d73f6a2e */           \
        0x60814a64, 0x61e9, 0x4fd9,                        \
        {                                                  \
            0x91, 0x59, 0xe1, 0x58, 0xd7, 0x3f, 0x6a, 0x2e \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                      \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "hostcalls test TA"}, \
    {                                                                     \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)         \
        {                                                                 \
            0x0010                                                        \
        }                                                                 \
    }
