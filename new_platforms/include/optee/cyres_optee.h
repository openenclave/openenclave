/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

oe_result_t get_cyres_seal_secret(
    const uint8_t* key_selector,
    size_t key_selector_size,
    uint8_t** secret,
    size_t* secret_size,
    size_t req_size);

oe_result_t get_cyres_private_key(uint8_t** key, size_t* key_size);

oe_result_t get_cyres_public_key(uint8_t** pem, size_t* pem_size);

oe_result_t get_cyres_cert_chain(uint8_t** pem, size_t* pem_size);
