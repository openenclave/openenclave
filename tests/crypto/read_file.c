// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "readfile.h"

oe_result_t read_cert(char* filename, char* cert)
{
    size_t len_cert;
    FILE* cfp = fopen(filename, "r");
    if (cfp != NULL)
    {
        len_cert = fread(cert, sizeof(char), max_cert_size, cfp);
    }
    else
    {
        return OE_FAILURE;
    }
    cert[len_cert] = '\0';
    fclose(cfp);
    return OE_OK;
}

oe_result_t read_chain(char* filename1, char* filename2, char* chain)
{
    size_t len_cert1 = 0, len_cert2 = 0;
    char chain_temp[max_cert_size];
    FILE* cfp1 = fopen(filename1, "r");
    FILE* cfp2 = fopen(filename2, "r");

    if (cfp1 != NULL && cfp2 != NULL)
    {
        len_cert1 = fread(chain, sizeof(char), max_cert_size, cfp1);
        chain[len_cert1] = '\0';
        len_cert2 = fread(chain_temp, sizeof(char), max_cert_size, cfp2);
        chain_temp[len_cert2] = '\0';
        strcat(chain, chain_temp);
    }
    else
    {
        return OE_FAILURE;
    }

    fclose(cfp1);
    fclose(cfp2);
    return OE_OK;
}

oe_result_t read_chains(
    char* filename1,
    char* filename2,
    char* filename3,
    char* chain)
{
    size_t len_cert1 = 0, len_cert2 = 0, len_cert3 = 0;
    char chain_temp1[max_cert_size];
    char chain_temp2[max_cert_size];
    FILE* cfp1 = fopen(filename1, "r");
    FILE* cfp2 = fopen(filename2, "r");
    FILE* cfp3 = fopen(filename3, "r");

    if (cfp1 != NULL && cfp2 != NULL && cfp3 != NULL)
    {
        len_cert1 = fread(chain, sizeof(char), max_cert_size, cfp1);
        chain[len_cert1] = '\0';
        len_cert2 = fread(chain_temp1, sizeof(char), max_cert_size, cfp2);
        chain_temp1[len_cert2] = '\0';
        len_cert3 = fread(chain_temp2, sizeof(char), max_cert_size, cfp3);
        chain_temp2[len_cert3] = '\0';
        strcat(chain, chain_temp1);
        strcat(chain, chain_temp2);
    }
    else
    {
        return OE_FAILURE;
    }
    fclose(cfp1);
    fclose(cfp2);
    fclose(cfp3);
    return OE_OK;
}

oe_result_t read_crl(char* filename, uint8_t* crl, size_t* crl_size)
{
    size_t len_crl = 0;
    FILE* cfp = fopen(filename, "rb");

    if (cfp != NULL)
    {
        len_crl = fread(crl, sizeof(char), max_cert_size, cfp);
    }
    else
    {
        return OE_FAILURE;
    }
    crl[len_crl] = '\0';
    *crl_size = len_crl;
    fclose(cfp);
    return OE_OK;
}

oe_result_t read_dates(char* filename, oe_datetime_t* time)
{
    size_t len_date = 0;
    char buffer[max_date_size];
    FILE* dfp = fopen(filename, "r");

    if (dfp != NULL)
    {
        len_date = fread(buffer, sizeof(char), max_date_size, dfp);
    }
    else
    {
        return OE_FAILURE;
    }
    buffer[len_date] = '\0';

    sscanf(
        buffer,
        "%u :%u :%u :%u :%u :%u",
        &(time->year),
        &(time->month),
        &(time->day),
        &(time->hours),
        &(time->minutes),
        &(time->seconds));

    fclose(dfp);
    return OE_OK;
}

oe_result_t read_mod(char* filename, uint8_t* mod, size_t* mod_size)
{
    size_t len_mod;
    FILE* mfp = fopen(filename, "r");
    if (mfp != NULL)
    {
        len_mod = fread(mod, sizeof(char), max_mod_size, mfp);
    }
    else
    {
        return OE_FAILURE;
    }

    mod[len_mod] = '\0';
    *mod_size = len_mod;
    fclose(mfp);
    return OE_OK;
}

oe_result_t read_mixed_chain(char* chain, char* chain1, char* chain2)
{
    char chain_temp[max_cert_chain_size * 2];
    OE_UNUSED(chain);

    strcat(chain_temp, chain1);
    strcat(chain_temp, chain2);
    chain = chain_temp;
    return OE_OK;
}

oe_result_t read_sign(char* filename, uint8_t* sign, size_t* sign_size)
{
    size_t len_sign;
    FILE* sfp = fopen(filename, "r");
    if (sfp != NULL)
    {
        len_sign = fread(sign, sizeof(char), max_sign_size, sfp);
    }
    else
    {
        return OE_FAILURE;
    }

    sign[len_sign] = '\0';
    *sign_size = len_sign;
    fclose(sfp);
    return OE_OK;
}

oe_result_t read_key(char* filename, char* key)
{
    size_t len_key;
    FILE* kfp = fopen(filename, "r");
    if (kfp != NULL)
    {
        len_key = fread(key, sizeof(char), max_key_size, kfp);
    }
    else
    {
        return OE_FAILURE;
    }
    key[len_key] = '\0';

    fclose(kfp);
    return OE_OK;
}

oe_result_t read_pem_key(char* filename, uint8_t* key, size_t* key_size)
{
    size_t len_key;
    FILE* kfp = fopen(filename, "r");
    if (kfp != NULL)
    {
        len_key = fread(key, sizeof(char), max_key_size, kfp);
    }
    else
    {
        return OE_FAILURE;
    }
    key[len_key] = '\0';
    *key_size = len_key;

    fclose(kfp);
    return OE_OK;
}

oe_result_t read_coordinates(
    char* filename,
    uint8_t* x,
    uint8_t* y,
    size_t* x_size,
    size_t* y_size)
{
    size_t len_x, len_y;
    FILE* cfp = fopen(filename, "r");
    if (cfp != NULL)
    {
        len_x = fread(x, sizeof(char), max_coordinates_size, cfp);
        len_y = fread(y, sizeof(char), max_coordinates_size, cfp);
    }
    else
    {
        return OE_FAILURE;
    }
    fclose(cfp);
    *x_size = len_x;
    *y_size = len_y;
    return OE_OK;
}
