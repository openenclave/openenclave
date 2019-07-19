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
    oe_quote_customization_plugin_context_t* plugin_context;
    oe_tee_evidence_type_t tee_evidence_type;
    uuid_t evidence_format_uuid;
    oe_quote_customization_plugin_callbacks_t* callbacks;
    struct attestation_plugin_t* next;
};

struct attestation_plugin_t* g_plugins = NULL;

void dump_attestation_plugin_list()
{
    struct attestation_plugin_t* cur = NULL;

    OE_TRACE_INFO(
        "Calling oe_register_attestation_plugin: evidence_format_uuid list\n");
    oe_mutex_lock(&g_plugin_list_mutex);
    cur = g_plugins;
    while (cur)
    {
        for (int i = 0; i < UUID_SIZE; i++)
        {
            OE_TRACE_INFO("0x%0x\n", cur->evidence_format_uuid.b[i]);
        }
        cur = cur->next;
    }
    oe_mutex_unlock(&g_plugin_list_mutex);
}

// convert oe_report_t parsed_report into an array of claims
int convert_parsed_report_to_claims(
    oe_report_t* parsed_report,
    oe_claim_element_t** claims,
    size_t* claim_count)
{
    int ret = 1;
    size_t count = 5; /* supports  security_version, unique_id, signer_id,
                         product_id, debug_flag*/
    oe_claim_element_t* all_claims = NULL;
    oe_identity_t* identity = NULL;

    identity = &parsed_report->identity;
    all_claims =
        (oe_claim_element_t*)oe_malloc(sizeof(oe_claim_element_t) * count);
    if (all_claims == NULL)
    {
        goto done;
    }
    oe_secure_zero_fill(all_claims, sizeof(oe_claim_element_t) * count);

    all_claims[0].name = "security_version";
    all_claims[0].len = sizeof(identity->security_version);
    all_claims[0].value = (uint8_t*)oe_malloc(all_claims[0].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy(
        (void*)all_claims[0].value,
        &identity->security_version,
        all_claims[0].len);

    // MRENCLAVE for SGX
    all_claims[1].name = "unique_id";
    all_claims[1].len = OE_UNIQUE_ID_SIZE;
    all_claims[1].value = (uint8_t*)oe_malloc(all_claims[1].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy((void*)all_claims[1].value, &identity->unique_id, all_claims[1].len);

    all_claims[2].name = "signer_id";
    all_claims[2].len = OE_SIGNER_ID_SIZE;
    all_claims[2].value = (uint8_t*)oe_malloc(all_claims[2].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy((void*)all_claims[2].value, &identity->signer_id, all_claims[2].len);

    all_claims[3].name = "product_id";
    all_claims[3].len = OE_PRODUCT_ID_SIZE;
    all_claims[3].value = (uint8_t*)oe_malloc(all_claims[3].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy(
        (void*)all_claims[3].value, &identity->product_id, all_claims[3].len);

    all_claims[4].name = "debug_flag";
    all_claims[4].len = 1;
    all_claims[4].value = (uint8_t*)oe_malloc(all_claims[4].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy(
        (void*)all_claims[4].value, &identity->product_id, all_claims[4].len);
    *(bool*)all_claims[4].value =
        (identity->attributes & OE_REPORT_ATTRIBUTES_DEBUG) ? 1 : 0;

    *claims = all_claims;
    *claim_count = count;
    ret = 0;

done:
    if (ret)
    {
        if (all_claims)
        {
            // free all memory
            for (size_t i = 0; i < count; i++)
                oe_free(all_claims[i].value);
            oe_free(all_claims);
        }
    }
    return ret;
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
                (void*)&cur->evidence_format_uuid,
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
    oe_quote_customization_plugin_context_t* context)
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

    plugin->tee_evidence_type = context->tee_evidence_type;
    memcpy(
        (void*)&plugin->evidence_format_uuid,
        &(context->evidence_format_uuid),
        sizeof(uuid_t));

    plugin->callbacks = context->callbacks;
    plugin->next = NULL;

    plugin->plugin_context = context;

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
    oe_quote_customization_plugin_context_t* context)
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
    uuid_t* evidence_format_uuid,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size)
{
    oe_result_t result = OE_FAILURE;
    struct attestation_plugin_t* plugin = NULL;
    oe_sha256_context_t sha256_ctx = {0};
    uint8_t* remote_report_buf = NULL;
    size_t remote_report_buf_size = sizeof(oe_evidence_header_t);
    uint8_t* total_evidence_buff = NULL;
    uint8_t* custom_data = NULL;
    size_t custom_evidence_size = 0;
    int ret = 1;

    // find a plugin for attestation type
    plugin = find_plugin(evidence_format_uuid, NULL);
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

    ret = plugin->callbacks->get_custom_evidence(
        plugin->plugin_context, &custom_data, &custom_evidence_size);
    if (ret != 0)
    {
        OE_TRACE_ERROR("get_custom_evidence failed with ret = %d", ret);
        goto done;
    }
    OE_TRACE_INFO("custom_evidence_size = %d", custom_evidence_size);

    //
    // plugin found
    //

    if (plugin->tee_evidence_type == OE_TEE_TYPE_SGX_REMOTE)
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
        // for non OE_TEE_TYPE_SGX_REMOTE report, reserve size for
        // oe_evidence_header_t
        remote_report_buf_size = sizeof(oe_evidence_header_t);
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
    if (plugin->tee_evidence_type == OE_TEE_TYPE_SGX_REMOTE)
    {
        oe_evidence_header_t* header =
            (oe_evidence_header_t*)total_evidence_buff;
        header->custom_evidence_size = (uint32_t)custom_evidence_size;
        memcpy(
            (void*)&header->evidence_format_uuid,
            evidence_format_uuid,
            sizeof(uuid_t));
    }
    else
    {
        oe_evidence_header_t* header =
            (oe_evidence_header_t*)total_evidence_buff;
        header->version = OE_REPORT_HEADER_VERSION; // TODO: change to 2
        header->tee_evidence_type = plugin->tee_evidence_type;
        header->evidence_format_uuid = plugin->evidence_format_uuid;
        header->tee_evidence_size = 0;
        header->custom_evidence_size = (uint32_t)custom_evidence_size;
        memcpy(
            (void*)&header->evidence_format_uuid,
            evidence_format_uuid,
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
    void* callback_context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    oe_claim_element_t** claims,
    size_t* claim_count)
{
    oe_result_t result = OE_FAILURE;
    struct attestation_plugin_t* plugin = NULL;
    uint64_t custom_evidence_size = 0;
    uint8_t* custom_data = NULL;
    int ret = 0;
    oe_evidence_header_t* header = (oe_evidence_header_t*)evidence_buffer;
    oe_report_t parsed_report;

    (void)callback_context;
    // OE_TRACE_INFO("evidence_format_uuid:%s", header->evidence_format_uuid);

    // TODO:
    // parse the attestation evidence header for attestation type (SGX,
    // TrustZone, Token)
    //

    // find a plugin by attestation_type
    // if not found, fallback to default operation if its a supported based TEE
    // type (SGX/TrustZone) find a plugin for attestation type
    plugin = find_plugin(&header->evidence_format_uuid, NULL);
    if (plugin == NULL)
    {
        // plugin not found
        goto done;
    }

    // Init claim output values
    *claims = NULL;
    *claim_count = 0;

    if (plugin->callbacks->verify_full_evidence != NULL)
    {
        // in this case, a plugin handles validation for the full quote
        // inclduing both normal quote and custom evedence
        ret = plugin->callbacks->verify_full_evidence(
            plugin->plugin_context,
            evidence_buffer,
            evidence_buffer_size,
            claims,
            claim_count);
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

    if (plugin->tee_evidence_type == OE_TEE_TYPE_SGX_REMOTE)
    {
        // call plugin callback to do only the custom evidence valdaiton
        result = oe_verify_report(
            evidence_buffer, evidence_buffer_size, &parsed_report);
        if (result != OE_OK)
        {
            OE_TRACE_ERROR(
                "oe_verify_report failed (%s).\n", oe_result_str(result));
            goto done;
        }

        // convert oe_report_t parsed_report into an array of claims
        ret = convert_parsed_report_to_claims(
            &parsed_report, claims, claim_count);
        if (ret != 0)
        {
            OE_TRACE_ERROR("convert_parsed_report_to_claims failed.\n");
            goto done;
        }

        // TODO: need to find out where the additional quote data starts
        // Should we record it in the header when quote was generated?
        //

        custom_data = header->tee_evidence + header->tee_evidence_size;
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
                parsed_report.report_data, (uint8_t*)&sha256, OE_SHA256_SIZE) !=
            0)
        {
            result = OE_VERIFY_FAILED;
            OE_TRACE_ERROR("report_data checking failed (%s).\n");
            goto done;
        }
    }

    ret = plugin->callbacks->verify_custom_evidence(
        plugin->plugin_context,
        header->tee_evidence + header->tee_evidence_size,
        header->custom_evidence_size,
        claims,
        claim_count);
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

void oe_free_claim_list(oe_claim_element_t* claims, size_t claim_count)
{
    if (claims)
    {
        // free all memory
        for (size_t i = 0; i < claim_count; i++)
            oe_free(claims[i].value);

        oe_free(claims);
    }
}