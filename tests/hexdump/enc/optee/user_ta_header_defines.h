/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* 126830b9-eb9f-412a-89a7-bcc8a517c12e */           \
        0x126830b9, 0xeb9f, 0x412a,                        \
        {                                                  \
            0x89, 0xa7, 0xbc, 0xc8, 0xa5, 0x17, 0xc1, 0x2e \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
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
