// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>

#include "../common/common.h"

// create an array to manage the all the registered plug-ins
// char GUID[40];

// // {6EBB65E5-F657-48B1-94DF-0EC0B671DA26}
// static const GUID <<name>> =
// { 0x6ebb65e5, 0xf657, 0x48b1, { 0x94, 0xdf, 0xe, 0xc0, 0xb6, 0x71, 0xda, 0x26
// } };

static oe_mutex_t g_plugin_list_mutex = OE_MUTEX_INITIALIZER;

struct attestation_plugin_t
{
    oe_report_type_t report_type;
    uuid_t evidence_format_id;
    oe_attestation_plugin_callbacks_t* ops;
    struct attestation_plugin_t* next;
};

struct attestation_plugin_t* g_plugins = NULL;

void dump_attestation_plugin_list()
{
    struct attestation_plugin_t* cur = NULL;

    OE_TRACE_INFO(
        "Calling oe_register_attestation_plugin: evidence_format_id list\n");
    oe_mutex_lock(&g_plugin_list_mutex);
    cur = g_plugins;
    while (cur)
    {
        for (int i = 0; i < UUID_SIZE; i++)
        {
            OE_TRACE_INFO("0x%0x\n", cur->evidence_format_id.b[i]);
        }
        cur = cur->next;
    }
    oe_mutex_unlock(&g_plugin_list_mutex);
}

struct attestation_plugin_t* find_plugin(
    uuid_t* target_evidence_format_uuid,
    struct attestation_plugin_t** prev)
{
    struct attestation_plugin_t* ret = NULL;
    struct attestation_plugin_t* cur = NULL;

    if (prev)
        *prev = NULL;

    // find a plugin for attestation type
    oe_mutex_lock(&g_plugin_list_mutex);
    cur = g_plugins;
    while (cur)
    {
        if (memcmp(
                (void*)&cur->evidence_format_id,
                (void*)target_evidence_format_uuid,
                sizeof(uuid_t)) == 0)
        {
            ret = cur;
            break;
        }
        if (prev)
            *prev = cur;
        cur = cur->next;
    }
    oe_mutex_unlock(&g_plugin_list_mutex);
    return ret;
}

// TODO: need synchronization
oe_result_t oe_register_attestation_plugin(
    oe_attestation_plugin_context_t* context)
{
    oe_result_t result = OE_FAILURE;
    struct attestation_plugin_t* plugin = NULL;

    OE_TRACE_INFO("Calling oe_register_attestation_plugin");

    plugin = find_plugin(&context->evidence_format_uuid, NULL);
    if (plugin)
    {
        OE_TRACE_ERROR(
            "Calling oe_register_attestation_plugin failed: "
            "evidence_format_uuid[%s] already existed",
            context->evidence_format_uuid);
        goto done;
    }

    plugin = (struct attestation_plugin_t*)oe_malloc(
        sizeof(struct attestation_plugin_t));
    if (plugin == NULL)
        goto done;

    plugin->report_type = context->report_type;
    memcpy(
        (void*)&plugin->evidence_format_id,
        &(context->evidence_format_uuid),
        sizeof(uuid_t));

    plugin->ops = context->ops;
    plugin->next = NULL;
    if (plugin->ops->init_plugin() != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    if (g_plugins == NULL)
    {
        g_plugins = plugin;
    }
    else
    {
        plugin->next = g_plugins;
        g_plugins = plugin;
    }
    dump_attestation_plugin_list();
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_unregister_attestation_plugin(
    oe_attestation_plugin_context_t* context)
// const unsigned char attestation_type[40])
{
    oe_result_t result = OE_FAILURE;
    struct attestation_plugin_t* prev = NULL;
    struct attestation_plugin_t* cur = g_plugins;

    OE_TRACE_INFO("Calling oe_unregister_attestation_plugin 1");

    // find the guid and remove it
    cur = find_plugin(&context->evidence_format_uuid, &prev);
    if (cur == NULL)
    {
        OE_TRACE_ERROR(
            "Calling oe_unregister_attestation_plugin failed: "
            "evidence_format_uuid[%s] was not registered before",
            context->evidence_format_uuid);
        goto done;
    }

    cur->ops->cleanup_plugin();
    oe_mutex_lock(&g_plugin_list_mutex);
    if (prev != NULL)
        prev->next = cur->next;
    else
        g_plugins = NULL;
    oe_mutex_unlock(&g_plugin_list_mutex);

    dump_attestation_plugin_list();

    result = OE_OK;
done:
    oe_free(cur);
    return result;
}

oe_result_t oe_get_attestation_evidence(
    uuid_t* evidence_format_id,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size)
{
    oe_result_t result = OE_FAILURE;
    struct attestation_plugin_t* plugin = NULL;
    oe_sha256_context_t sha256_ctx = {0};
    uint8_t* remote_report_buf = NULL;
    size_t remote_report_buf_size = sizeof(oe_report_header_t);
    uint8_t* total_evidence_buff = NULL;
    uint8_t* custom_data = NULL;
    size_t custom_evidence_size = 0;
    int ret = 1;

    // find a plugin for attestation type
    plugin = find_plugin(evidence_format_id, NULL);
    if (plugin == NULL)
    {
        // no plugin found, perform default operation

        // DO default get report if the type is one of SGX or TrustZone
        // otherwise, fail out
        // result = oe_get_report(
        //     OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        //     (const uint8_t*)&sha256,
        //     OE_SHA256_SIZE,
        //     NULL,
        //     0,
        //     &remote_report_buf,
        //     &remote_report_buf_size);
        goto done;
    }

    //
    // get custom evidence data from the plugin
    //
    ret = plugin->ops->get_custom_evidence_size(&custom_evidence_size);
    if (ret != 0)
    {
        OE_TRACE_ERROR("get_custom_evidence_size failed with ret = %d", ret);
        goto done;
    }

    OE_TRACE_INFO("custom_evidence_size = %d", custom_evidence_size);

    custom_data = (uint8_t*)oe_malloc(custom_evidence_size);
    if (custom_data == NULL)
    {
        OE_TRACE_ERROR("failed to allocate memory for custom evidence data");
        goto done;
    }

    ret = plugin->ops->get_custom_evidence(custom_data, custom_evidence_size);
    if (ret != 0)
    {
        OE_TRACE_ERROR("get_custom_evidence failed with ret = %d", ret);
        goto done;
    }

    //
    // plugin found
    //

    if (plugin->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        // generate hash for custom data
        OE_SHA256 sha256 = {0};
        oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
        OE_CHECK(oe_sha256_init(&sha256_ctx));
        OE_CHECK(
            oe_sha256_update(&sha256_ctx, custom_data, custom_evidence_size));
        OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

        // get remote report
        // TODO: file a bug on this, why setting to remote_report_buf_size to
        // OE_MAX_REPORT_SIZE is needed?
        result = oe_get_report(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            (const uint8_t*)&sha256,
            OE_SHA256_SIZE,
            NULL,
            0,
            &remote_report_buf,
            &remote_report_buf_size);
        if (result != OE_OK)
        {
            OE_TRACE_ERROR("oe_get_report failed %s", oe_result_str(result));
            goto done;
        }
    }
    else
    {
        // for non OE_REPORT_TYPE_SGX_REMOTE report, reserve size for
        // oe_report_header_t
        remote_report_buf_size = sizeof(oe_report_header_t);
    }

    //

    // allocate a buffer big enough to hold header, quote, and custom data
    // calls needs to call oe_free_attestation_certificate to free this memory
    total_evidence_buff =
        (uint8_t*)oe_malloc(remote_report_buf_size + custom_evidence_size);
    if (total_evidence_buff == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    if (remote_report_buf)
        memcpy(total_evidence_buff, remote_report_buf, remote_report_buf_size);

    memcpy(
        total_evidence_buff + remote_report_buf_size,
        custom_data,
        custom_evidence_size);

    // update header
    if (plugin->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        oe_report_header_t* header = (oe_report_header_t*)total_evidence_buff;
        header->custom_evidence_size = custom_evidence_size;
        memcpy(
            (void*)&header->evidence_format,
            evidence_format_id,
            sizeof(uuid_t));
    }
    else
    {
        oe_report_header_t* header = (oe_report_header_t*)total_evidence_buff;
        header->version = OE_REPORT_HEADER_VERSION; // TODO: change to 2
        header->report_type = plugin->report_type;
        header->evidence_format = plugin->evidence_format_id;
        header->report_size = 0;
        header->custom_evidence_size = custom_evidence_size;
        memcpy(
            (void*)&header->evidence_format,
            evidence_format_id,
            sizeof(uuid_t));
    }

    *evidence_buffer = total_evidence_buff;
    *evidence_buffer_size = remote_report_buf_size + custom_evidence_size;
    result = OE_OK;

done:
    oe_free(custom_data);
    oe_free(remote_report_buf);
    return result;
}

void oe_free_attestation_evidence(uint8_t* evidence_buffer)
{
    oe_free(evidence_buffer);
}

oe_result_t oe_verify_attestation_evidence(
    void* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_FAILURE;
    struct attestation_plugin_t* plugin = NULL;
    uint64_t custom_evidence_size = 0;
    uint8_t* custom_data = NULL;
    int ret = 0;
    oe_report_header_t* header = (oe_report_header_t*)evidence_buffer;

    // OE_TRACE_INFO("evidence_format:%s", header->evidence_format);

    // TODO:
    // parse the attestation evidence header for attestation type (SGX,
    // TrustZone, Token)
    //

    // find a plugin by attestation_type
    // if not found, fallback to default operation if its a supported based TEE
    // type (SGX/TrustZone) find a plugin for attestation type
    plugin = find_plugin(&header->evidence_format, NULL);
    if (plugin == NULL)
    {
        // plugin not found
        goto done;
    }

    if (plugin->ops->verify_full_evidence != NULL)
    {
        // in this case, a plugin handles validation for the full quote
        // inclduing both normal quote and custom evedence
        ret = plugin->ops->verify_full_evidence(
            context, evidence_buffer, evidence_buffer_size, parsed_report);
        if (ret != 0)
        {
            result = OE_VERIFY_FAILED;
            OE_TRACE_ERROR(
                "verify_full_evidence failed (%s).\n", oe_result_str(result));
        }
        else
        {
            result = OE_OK;
            OE_TRACE_INFO(
                "verify_full_evidence failed (%s).\n", oe_result_str(result));
        }
        goto done;
    }

    if (plugin->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        // call plugin callback to do only the custom evidence valdaiton
        result = oe_verify_report(
            evidence_buffer, evidence_buffer_size, parsed_report);
        if (result != OE_OK)
        {
            OE_TRACE_ERROR(
                "oe_verify_report failed (%s).\n", oe_result_str(result));
            goto done;
        }

        // TODO: need to find out where the additional quote data starts
        // Should we record it in the header when quote was generated?
        //

        custom_data = header->report + header->report_size;
        custom_evidence_size = header->custom_evidence_size;

        // verify hash for custom data
        // calculate hash of custom_data and compare it with report data in
        // parsed_report
        oe_sha256_context_t sha256_ctx = {0};
        OE_SHA256 sha256 = {0};
        oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
        OE_CHECK(oe_sha256_init(&sha256_ctx));
        OE_CHECK(
            oe_sha256_update(&sha256_ctx, custom_data, custom_evidence_size));
        OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

        if (memcmp(
                parsed_report->report_data,
                (uint8_t*)&sha256,
                OE_SHA256_SIZE) != 0)
        {
            result = OE_VERIFY_FAILED;
            OE_TRACE_ERROR("report_data checking failed (%s).\n");
            goto done;
        }
    }

    ret = plugin->ops->verify_custom_evidence(
        context,
        header->report + header->report_size,
        header->custom_evidence_size,
        (plugin->report_type == OE_REPORT_TYPE_SGX_REMOTE) ? parsed_report
                                                           : NULL);
    if (ret != 0)
    {
        result = OE_VERIFY_FAILED;
        OE_TRACE_ERROR(
            "oe_verify_report failed (%s).\n", oe_result_str(result));
        goto done;
    }

    result = OE_OK;
done:
    return result;
}
