/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 952c55c8-59f3-47a0-814c-ae3276a9808f */           \
        0x952c55c8, 0x59f3, 0x47a0,                        \
        {                                                  \
            0x81, 0x4c, 0xae, 0x32, 0x76, 0xa9, 0x80, 0x8f \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                                        \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING, "mixed C/C++ test TA"}, \
    {                                                                       \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t)           \
        {                                                                   \
            0x0010                                                          \
        }                                                                   \
    }
