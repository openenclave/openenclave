// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <ctype.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/corelibc/string.h>
#else
#include "../../host/strings.h"
#endif

#include "readfile.h"

FILE* read_file(const char* filename, const char* mode)
{
    FILE* file;
#ifdef _MSC_VER
    fopen_s(&file, filename, mode);
#else
    file = fopen(filename, mode);
#endif
    return file;
}

oe_result_t read_cert(char* dir, char* filename, char* cert)
{
    size_t len_cert;
    char* abspath = NULL;

    abspath = (char*)malloc(strlen(dir) + strlen(filename) + 2);
    snprintf(
        abspath, strlen(dir) + strlen(filename) + 2, "%s/%s", dir, filename);

    FILE* cfp = read_file(abspath, "rb");
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
    free(abspath);
    return OE_OK;
}

oe_result_t read_chain(
    char* dir,
    char* filename1,
    char* filename2,
    char* chain,
    size_t chain_size)
{
    size_t len_cert1 = 0, len_cert2 = 0;
    char chain_temp[max_cert_size];
    char* abspath1 = NULL;
    char* abspath2 = NULL;

    abspath1 = (char*)malloc(strlen(dir) + strlen(filename1) + 2);
    abspath2 = (char*)malloc(strlen(dir) + strlen(filename2) + 2);
    snprintf(
        abspath1, strlen(dir) + strlen(filename1) + 2, "%s/%s", dir, filename1);
    snprintf(
        abspath2, strlen(dir) + strlen(filename2) + 2, "%s/%s", dir, filename2);
    FILE* cfp1 = read_file(abspath1, "rb");
    FILE* cfp2 = read_file(abspath2, "rb");

    if (cfp1 != NULL && cfp2 != NULL)
    {
        len_cert1 = fread(chain, sizeof(char), max_cert_size, cfp1);
        chain[len_cert1] = '\0';
        len_cert2 = fread(chain_temp, sizeof(char), max_cert_size, cfp2);
        chain_temp[len_cert2] = '\0';
        oe_strlcat(chain, chain_temp, chain_size);
    }
    else
    {
        return OE_FAILURE;
    }

    free(abspath1);
    free(abspath2);
    fclose(cfp1);
    fclose(cfp2);
    return OE_OK;
}

oe_result_t read_chains(
    char* dir,
    char* filename1,
    char* filename2,
    char* filename3,
    char* chain,
    size_t chain_size)
{
    size_t len_cert1 = 0, len_cert2 = 0, len_cert3 = 0;
    char chain_temp1[max_cert_size];
    char chain_temp2[max_cert_size];
    char* abspath1 = NULL;
    char* abspath2 = NULL;
    char* abspath3 = NULL;

    abspath1 = (char*)malloc(strlen(dir) + strlen(filename1) + 2);
    abspath2 = (char*)malloc(strlen(dir) + strlen(filename2) + 2);
    abspath3 = (char*)malloc(strlen(dir) + strlen(filename3) + 2);
    snprintf(
        abspath1, strlen(dir) + strlen(filename1) + 2, "%s/%s", dir, filename1);
    snprintf(
        abspath2, strlen(dir) + strlen(filename2) + 2, "%s/%s", dir, filename2);
    snprintf(
        abspath3, strlen(dir) + strlen(filename3) + 2, "%s/%s", dir, filename3);
    FILE* cfp1 = read_file(abspath1, "rb");
    FILE* cfp2 = read_file(abspath2, "rb");
    FILE* cfp3 = read_file(abspath3, "rb");

    if (cfp1 != NULL && cfp2 != NULL && cfp3 != NULL)
    {
        len_cert1 = fread(chain, sizeof(char), max_cert_size, cfp1);
        chain[len_cert1] = '\0';
        len_cert2 = fread(chain_temp1, sizeof(char), max_cert_size, cfp2);
        chain_temp1[len_cert2] = '\0';
        len_cert3 = fread(chain_temp2, sizeof(char), max_cert_size, cfp3);
        chain_temp2[len_cert3] = '\0';
        oe_strlcat(chain, chain_temp1, chain_size);
        oe_strlcat(chain, chain_temp2, chain_size);
    }
    else
    {
        return OE_FAILURE;
    }
    free(abspath1);
    free(abspath2);
    free(abspath3);
    fclose(cfp1);
    fclose(cfp2);
    fclose(cfp3);
    return OE_OK;
}

oe_result_t read_crl(char* dir, char* filename, uint8_t* crl, size_t* crl_size)
{
    size_t len_crl = 0;
    char* abspath = NULL;

    abspath = (char*)malloc(strlen(dir) + strlen(filename) + 2);
    snprintf(
        abspath, strlen(dir) + strlen(filename) + 2, "%s/%s", dir, filename);
    FILE* cfp = read_file(abspath, "rb");

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
    free(abspath);
    return OE_OK;
}

oe_result_t read_dates(char* dir, char* filename, oe_datetime_t* time)
{
    size_t len_date = 0;
    char buffer[max_date_size];
    char* abspath = NULL;

    abspath = (char*)malloc(strlen(dir) + strlen(filename) + 2);
    snprintf(
        abspath, strlen(dir) + strlen(filename) + 2, "%s/%s", dir, filename);
    FILE* dfp = read_file(abspath, "rb");

    if (dfp != NULL)
    {
        len_date = fread(buffer, sizeof(char), max_date_size, dfp);
    }
    else
    {
        return OE_FAILURE;
    }
    buffer[len_date] = '\0';

    sscanf_s(
        buffer,
        "%u :%u :%u :%u :%u :%u",
        &(time->year),
        &(time->month),
        &(time->day),
        &(time->hours),
        &(time->minutes),
        &(time->seconds));

    fclose(dfp);
    free(abspath);
    return OE_OK;
}

static uint8_t hexval(char c)

{
    switch (c)
    {
        case 'A':
            return 10;
        case 'B':
            return 11;
        case 'C':
            return 12;
        case 'D':
            return 13;
        case 'E':
            return 14;
        case 'F':
            return 15;
        case 'a':
            return 10;
        case 'b':
            return 11;
        case 'c':
            return 12;
        case 'd':
            return 13;
        case 'e':
            return 14;
        case 'f':
            return 15;

        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;

        default:
            return 0xff;
    }
}

// Assume a series of hex digits in the file.
oe_result_t read_mod(char* dir, char* filename, uint8_t* mod, size_t* mod_size)
{
    size_t len_mod;
    size_t numchars = 0;
    char buffer[(max_mod_size * 2) + 1];
    char* bufp = buffer;
    char* abspath = NULL;

    abspath = (char*)malloc(strlen(dir) + strlen(filename) + 2);
    snprintf(
        abspath, strlen(dir) + strlen(filename) + 2, "%s/%s", dir, filename);
    FILE* mfp = read_file(abspath, "rb");
    if (mfp != NULL)
    {
        numchars = fread(buffer, sizeof(char), max_mod_size * 2, mfp);
        // Skip leading non-digits ("Modulus=" for example).
        len_mod = numchars;

        for (size_t i = 0; i < numchars; i++)
        {
            if ((isdigit(*bufp) || (*bufp >= 'A' && *bufp <= 'F')))
                break;
            bufp++;
            len_mod--;
        }
    }
    else
    {
        return OE_FAILURE;
    }

    len_mod >>= 1;
    memset(mod, 0, len_mod + 1);
    for (size_t i = 0; i < len_mod; i++)
    {
        mod[i] = (uint8_t)(hexval(bufp[1]) + (hexval(bufp[0]) << 4));
        bufp += 2;
    }

    *mod_size = len_mod;
    fclose(mfp);
    free(abspath);
    return OE_OK;
}

oe_result_t read_mixed_chain(
    char* chain1,
    char* chain2,
    char* chain,
    size_t chain_size)
{
    oe_strlcat(chain, chain1, chain_size);
    oe_strlcat(chain, chain2, chain_size);
    return OE_OK;
}

oe_result_t read_sign(
    char* dir,
    char* filename,
    uint8_t* sign,
    size_t* sign_size)
{
    size_t len_sign;
    char* abspath = NULL;

    abspath = (char*)malloc(strlen(dir) + strlen(filename) + 2);
    snprintf(
        abspath, strlen(dir) + strlen(filename) + 2, "%s/%s", dir, filename);
    FILE* sfp = read_file(abspath, "rb");
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
    free(abspath);
    return OE_OK;
}

oe_result_t read_pem_key(
    char* dir,
    const char* filename,
    char* data,
    size_t data_size,
    size_t* data_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t size = 0;
    FILE* stream = NULL;
    int c;
    char* abspath = NULL;

    if (!filename || !data)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    abspath = (char*)malloc(strlen(dir) + strlen(filename) + 2);
    snprintf(
        abspath, strlen(dir) + strlen(filename) + 2, "%s/%s", dir, filename);
    /* Open file in binary mode. */
    if (!(stream = read_file(abspath, "rb")))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Read character-by-character, removing any <CR> characters. */
    while ((c = fgetc(stream)) != EOF && size < data_size)
    {
        if (c != '\r')
            data[size++] = (char)c;
    }

    if (size == data_size)
    {
        result = OE_BUFFER_TOO_SMALL;
        goto done;
    }

    data[size] = '\0';

    if (data_size_out)
        *data_size_out = size;

    result = OE_OK;

done:

    free(abspath);

    if (stream)
        fclose(stream);

    return result;
}

oe_result_t read_coordinates(
    char* dir,
    char* filename,
    uint8_t* x,
    uint8_t* y,
    size_t* x_size,
    size_t* y_size)
{
    size_t len_x, len_y;
    char* abspath = NULL;

    abspath = (char*)malloc(strlen(dir) + strlen(filename) + 2);
    snprintf(
        abspath, strlen(dir) + strlen(filename) + 2, "%s/%s", dir, filename);
    FILE* cfp = read_file(abspath, "rb");
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
    free(abspath);
    *x_size = len_x;
    *y_size = len_y;
    return OE_OK;
}
