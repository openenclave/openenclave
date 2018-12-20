// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _READFILE_H_
#define _READFILE_H_

#include <openenclave/bits/result.h>
#include <openenclave/internal/datetime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define max_key_size 2000
#define max_cert_size 2000
#define max_mod_size 1000
#define max_sign_size 1000
/* max_cert_chain_size for 2 certificate concatenation */
#define max_cert_chain_size 4000
/* max_cert_chains_size for 3 certificate concatenation */
#define max_cert_chains_size 6000
#define max_date_size 21
#define max_date_elements 6
#define max_coordinates_size 32

oe_result_t read_cert(char* filename, char* cert);

oe_result_t read_chain(char* filename1, char* filename2, char* chain);

oe_result_t read_chains(
    char* filename1,
    char* filename2,
    char* filename3,
    char* chain);

oe_result_t read_crl(char* filename, uint8_t* crl, size_t* crl_size);

oe_result_t read_dates(char* filename, oe_datetime_t* time);

oe_result_t read_mod(char* filename, uint8_t* mod, size_t* mod_size);

oe_result_t read_mixed_chain(char* chain, char* chain1, char* chain2);

oe_result_t read_sign(char* filename, uint8_t* sign, size_t* sign_size);

oe_result_t read_key(char* filename, char* key);

oe_result_t read_pem_key(char* filename, uint8_t* key, size_t* key_size);

oe_result_t read_coordinates(
    char* filename,
    uint8_t* x,
    uint8_t* y,
    size_t* x_size,
    size_t* y_size);

#endif //_READFILE_H_
