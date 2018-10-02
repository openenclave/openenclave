// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H_
#define _ARGS_H_

struct test_cert_chain_args_t
{
    const char* root;
    const char* intermediate;
    const char* leaf;
    const char* leaf2;
};

struct test_crl_args_t
{
    const char* root;
    const char* intermediate;
    const char* leaf1;
    const char* leaf2;
    const uint8_t* root_crl1;
    size_t root_crl1_size;
    const uint8_t* root_crl2;
    size_t root_crl2_size;
    const uint8_t* intermediate_crl1;
    size_t intermediate_crl1_size;
    const uint8_t* intermediate_crl2;
    size_t intermediate_crl2_size;
};

#endif //_ARGS_H_
