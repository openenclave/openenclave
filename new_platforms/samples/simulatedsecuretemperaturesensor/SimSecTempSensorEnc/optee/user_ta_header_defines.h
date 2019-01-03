/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID { /* 97d140f4-5f59-4d1f-9735-cb21d49e7eb8 */ \
    0x97d140f4, \
    0x5f59, \
    0x4d1f, \
    {0x97, 0x35, 0xcb, 0x21, 0xd4, 0x9e, 0x7e, 0xb8} \
  }

#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE               (12 * 1024)        /* 12 KB */
#define TA_DATA_SIZE                (1 * 1024 * 1024)  /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "SimSecTempSensor TA" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }
