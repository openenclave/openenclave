// Copyright (c) Open Enclave SDK contributors.
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

#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

oe_result_t read_cert(char* filename, char* cert);

oe_result_t read_chain(
    char* filename1,
    char* filename2,
    char* chain,
    size_t chain_size);

oe_result_t read_chains(
    char* filename1,
    char* filename2,
    char* filename3,
    char* chain,
    size_t chain_size);

oe_result_t read_crl(char* filename, uint8_t* crl, size_t* crl_size);

oe_result_t read_dates(char* filename, oe_datetime_t* time);

FILE* read_file(const char* filename, const char* mode);

oe_result_t read_mod(char* filename, uint8_t* mod, size_t* mod_size);

oe_result_t read_mixed_chain(
    char* chain1,
    char* chain2,
    char* chain,
    size_t chain_size);

oe_result_t read_sign(char* filename, uint8_t* sign, size_t* sign_size);

oe_result_t read_pem_key(
    const char* filename,
    char* data,
    size_t data_size,
    size_t* data_size_out);

oe_result_t read_coordinates(
    char* filename,
    uint8_t* x,
    uint8_t* y,
    size_t* x_size,
    size_t* y_size);

#endif //_READFILE_H_
