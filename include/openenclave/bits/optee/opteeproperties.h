// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Additional copyrights follow:

// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef _OE_OPTEE_HEADER_H
#define _OE_OPTEE_HEADER_H

#include <trace.h>
#include <user_ta_header.h>

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/bits/defs.h>

#define TA_FRAMEWORK_STACK_SIZE 2048

#define OE_TA_HEAD_SECTION_NAME ".ta_head"
#define OE_TA_HEAD_SECTION_BEGIN \
    OE_EXTERNC __attribute__((section(OE_TA_HEAD_SECTION_NAME)))
#define OE_TA_HEAD_SECTION_END

extern const char trace_ext_prefix[];
extern int trace_level;

struct utee_params;
void __utee_entry(
    unsigned long func,
    unsigned long session_id,
    struct utee_params* up,
    unsigned long cmd_id) OE_NO_RETURN;

// clang-format off
#define OE_SET_ENCLAVE_OPTEE(                                           \
    UUID,                                                               \
    HEAP_SIZE,                                                          \
    STACK_SIZE,                                                         \
    FLAGS,                                                              \
    VERSION,                                                            \
    DESCRIPTION)                                                        \
                                                                        \
    OE_TA_HEAD_SECTION_BEGIN                                            \
    volatile const struct ta_head ta_head =                             \
    {                                                                   \
        .uuid = UUID,                                                   \
        .stack_size = (STACK_SIZE) + TA_FRAMEWORK_STACK_SIZE,           \
        .flags = (FLAGS),                                               \
        .entry.ptr64 = (uint64_t)__utee_entry,                          \
        .rva = 0,                                                       \
    };                                                                  \
    OE_TA_HEAD_SECTION_END                                              \
                                                                        \
    uint8_t ta_heap[(HEAP_SIZE)];                                       \
    const size_t ta_heap_size = sizeof(ta_heap);                        \
                                                                        \
    const struct user_ta_property ta_props[] = {                        \
        {TA_PROP_STR_SINGLE_INSTANCE, USER_TA_PROP_TYPE_BOOL,           \
         &(const bool){((FLAGS) & TA_FLAG_SINGLE_INSTANCE) != 0}},      \
                                                                        \
        {TA_PROP_STR_MULTI_SESSION, USER_TA_PROP_TYPE_BOOL,             \
         &(const bool){((FLAGS) & TA_FLAG_MULTI_SESSION) != 0}},        \
                                                                        \
        {TA_PROP_STR_KEEP_ALIVE, USER_TA_PROP_TYPE_BOOL,                \
         &(const bool){((FLAGS) & TA_FLAG_INSTANCE_KEEP_ALIVE) != 0}},  \
                                                                        \
        {TA_PROP_STR_DATA_SIZE, USER_TA_PROP_TYPE_U32,                  \
         &(const uint32_t){(FLAGS)}},                                   \
                                                                        \
        {TA_PROP_STR_STACK_SIZE, USER_TA_PROP_TYPE_U32,                 \
         &(const uint32_t){(FLAGS)}},                                   \
                                                                        \
        {TA_PROP_STR_VERSION, USER_TA_PROP_TYPE_STRING,                 \
         (VERSION)},                                                    \
                                                                        \
        {TA_PROP_STR_DESCRIPTION, USER_TA_PROP_TYPE_STRING,             \
         (DESCRIPTION)},                                                \
    };                                                                  \
                                                                        \
    const size_t ta_num_props = sizeof(ta_props) / sizeof(ta_props[0]);

// clang-format on

#endif /* _OE_OPTEE_HEADER_H */
