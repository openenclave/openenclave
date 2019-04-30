/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID { /* [[generated-uuid]] */ \
    [[generated-uuid-part-1]], \
    [[generated-uuid-part-2]], \
    [[generated-uuid-part-3]], \
    {[[generated-uuid-part-4-a]], [[generated-uuid-part-4-b]], [[generated-uuid-part-5-a]], [[generated-uuid-part-5-b]], [[generated-uuid-part-5-c]], [[generated-uuid-part-5-d]], [[generated-uuid-part-5-e]], [[generated-uuid-part-5-f]]} \
  }

#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE               (12 * 1024)        /* 12 KB */
#define TA_DATA_SIZE                (1 * 1024 * 1024)  /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "[[project-name]] TA" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }
