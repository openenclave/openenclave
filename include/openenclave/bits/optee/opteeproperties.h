// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Additional copyrights follow:

// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef _OE_BITS_OPTEE_OPTEEPROPERTIES_H
#define _OE_BITS_OPTEE_OPTEEPROPERTIES_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/bits/defs.h>

OE_EXTERNC_BEGIN

#include <trace.h>
#include <user_ta_header.h>

#define TA_FRAMEWORK_STACK_SIZE 2048

#define OE_TA_HEAD_SECTION_NAME ".ta_head"
#define OE_TA_HEAD_SECTION_BEGIN \
    OE_EXTERNC __attribute__((section(OE_TA_HEAD_SECTION_NAME)))
#define OE_TA_HEAD_SECTION_END

struct utee_params;
void __utee_entry(
    unsigned long func,
    unsigned long session_id,
    struct utee_params* up,
    unsigned long cmd_id) OE_NO_RETURN;

/**
 * Defines the OP-TEE properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled into
 * an enclave binary.
 *
 * @param UUID Identifer used by OP-TEE and the non-secure OP-TEE supplicant to
 * find the enclave
 * @param HEAP_SIZE Size of the enclave's heap, in bytes
 * @param STACK_SIZE Size of the enclave's stack, in bytes
 * @param FLAGS GlobalPlatform TA_* flags
 * @param VERSION Version string (i.e., "1.0.0")
 * @param DESCRIPTION A string that describes the enclave
 */

// Some of the extra fluff in the macro, like the _oe_ta_* locals, is required
// to for it to function correctly when used in a C++ file.

// clang-format off
#define OE_SET_ENCLAVE_OPTEE(                                   \
    UUID,                                                       \
    HEAP_SIZE,                                                  \
    STACK_SIZE,                                                 \
    FLAGS,                                                      \
    VERSION,                                                    \
    DESCRIPTION)                                                \
                                                                \
    OE_EXTERNC_BEGIN                                            \
                                                                \
    OE_TA_HEAD_SECTION_BEGIN                                    \
    volatile const struct ta_head ta_head =                     \
    {                                                           \
        .uuid = UUID,                                           \
        .stack_size = (STACK_SIZE) + TA_FRAMEWORK_STACK_SIZE,   \
        .flags = (FLAGS),                                       \
        .entry =                                                \
        {                                                       \
            .ptr64 = (uint64_t)__utee_entry,                    \
        },                                                      \
        .rva = 0,                                               \
    };                                                          \
    OE_TA_HEAD_SECTION_END                                      \
                                                                \
    OE_USED uint8_t ta_heap[(HEAP_SIZE)];                       \
    OE_USED size_t ta_heap_size = sizeof(ta_heap);              \
                                                                \
    const bool _oe_ta_flag_single_instance =                    \
        {((FLAGS) & TA_FLAG_SINGLE_INSTANCE) != 0};             \
                                                                \
    const bool _oe_ta_flag_multi_session =                      \
        {((FLAGS) & TA_FLAG_MULTI_SESSION) != 0};               \
                                                                \
    const bool _oe_ta_flag_instance_keep_alive =                \
        {((FLAGS) & TA_FLAG_INSTANCE_KEEP_ALIVE) != 0};         \
                                                                \
    const uint32_t _oe_ta_heap_size  =                          \
        {(HEAP_SIZE)};                                          \
                                                                \
    const uint32_t _oe_ta_stack_size =                          \
        {(STACK_SIZE)};                                         \
                                                                \
    const struct user_ta_property ta_props[] =                  \
    {                                                           \
        {                                                       \
            TA_PROP_STR_SINGLE_INSTANCE,                        \
            USER_TA_PROP_TYPE_BOOL,                             \
            &_oe_ta_flag_single_instance                        \
        },                                                      \
        {                                                       \
            TA_PROP_STR_MULTI_SESSION,                          \
            USER_TA_PROP_TYPE_BOOL,                             \
            &_oe_ta_flag_multi_session                          \
        },                                                      \
        {                                                       \
            TA_PROP_STR_KEEP_ALIVE,                             \
            USER_TA_PROP_TYPE_BOOL,                             \
            &_oe_ta_flag_instance_keep_alive                    \
        },                                                      \
        {                                                       \
            TA_PROP_STR_DATA_SIZE,                              \
            USER_TA_PROP_TYPE_U32,                              \
            &_oe_ta_heap_size                                   \
        },                                                      \
        {                                                       \
            TA_PROP_STR_STACK_SIZE,                             \
            USER_TA_PROP_TYPE_U32,                              \
            &_oe_ta_stack_size                                  \
        },                                                      \
        {                                                       \
            TA_PROP_STR_VERSION,                                \
            USER_TA_PROP_TYPE_STRING,                           \
            (VERSION)                                           \
        },                                                      \
        {                                                       \
            TA_PROP_STR_DESCRIPTION,                            \
            USER_TA_PROP_TYPE_STRING,                           \
            (DESCRIPTION)                                       \
        },                                                      \
    };                                                          \
                                                                \
    const size_t ta_num_props =                                 \
        sizeof(ta_props) / sizeof(ta_props[0]);                 \
                                                                \
    OE_EXTERNC_END

// clang-format on

OE_EXTERNC_END

#endif /* _OE_BITS_OPTEE_OPTEEPROPERTIES_H */
