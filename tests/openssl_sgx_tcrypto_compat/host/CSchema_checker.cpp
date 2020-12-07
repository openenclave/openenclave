// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <new>

#include "CSchema_checker.h"
#include "include_openssl.h"

CSchemaChecker::CSchemaChecker(t_openssl_schema* schema, uint schema_size)
{
    m_schema_idx = 0;
    m_schema_num_apis = schema_size;

    memset(m_p1.p, 0, sizeof(m_p1.p));
    memset(m_p2.p, 0, sizeof(m_p2.p));
    if (schema)
    {
        m_schema =
            (t_openssl_schema*)new (std::nothrow) t_openssl_schema[schema_size];
        if (!m_schema)
            throw "Error allocating schema in CSchemaChecker constructor";

        for (uint i = 0; i < schema_size; i++)
            m_schema[i] = schema[i];
    }
    else
        m_schema = nullptr;
}
CSchemaChecker::~CSchemaChecker()
{
    CleanUpParams();

    if (m_schema)
        delete[] m_schema;
}

void CSchemaChecker::randomize_api_param(openssl_api_param* p)
{
    // for 1 api - randomize params
    uint64_t type;
    size_t len;
    char* buffer;
    if (!m_schema)
        return;

    t_openssl_schema* api_schema = &m_schema[m_schema_idx];
    for (int i = 0; i < OPENSSL_MAX_PARAMETER_COUNT; i++)
    {
        buffer = p->p[i];
        type = api_schema->type[i];
        if (!SSL_VALID(type))
            break;

        if (SSL_FIXLEN(type))
        {
            len = api_schema->length[i];
            for (size_t j = 0; j < len; j++)
                buffer[j] = (char)(rand());
            OverideRandomizedValue(
                m_api_id, (uint)i, type, 1, (unsigned char*)buffer, (uint)len);
        }
        else if (SSL_VARLEN_X(type))
        {
            len = (size_t)m_varlen_values[SSL_WHICH_VARLEN(type)];
            for (size_t j = 0; j < len; j++)
                buffer[j] = (char)(rand());
            OverideRandomizedValue(
                m_api_id, (uint)i, type, 1, (unsigned char*)buffer, (uint)len);
        }
    }
}

void CSchemaChecker::copy_api_param(
    openssl_api_param* p2,
    openssl_api_param* p1)
{
    uint64_t type;
    size_t len;

    if (!m_schema)
        return;
    t_openssl_schema* api_schema = &m_schema[m_schema_idx];

    assert(p1->id == p2->id);
    for (int i = 0; i < OPENSSL_MAX_PARAMETER_COUNT; i++)
    {
        char* b1 = p1->p[i];
        char* b2 = p2->p[i];

        type = api_schema->type[i];
        if (!SSL_VALID(type))
            break;

        if (SSL_FIXLEN(type))
        {
            len = api_schema->length[i];

            p2->p[i] = new (std::nothrow) char[len];
            b2 = p2->p[i];
            assert(b2);
            memcpy(b2, b1, len);
        }
        else if (SSL_VARLEN_X(type))
        {
            len = (size_t)m_varlen_values[SSL_WHICH_VARLEN(type)];
            p2->p[i] = new (std::nothrow) char[len];
            assert(NULL != p2->p[i]);
            b2 = p2->p[i];
            memcpy(b2, b1, len);
        }
        else if (SSL_LEN_X(type))
        {
            p2->p[i] = p1->p[i];
        }
    }
}

int CSchemaChecker::check_openssl(openssl_api_param* p1, openssl_api_param* p2)
{
    assert(p1->id == p2->id);

    return 0;
}

int CSchemaChecker::SetupParams(openssl_api_id id, uint schema_id)
{
    // per 1 api
    m_api_id = id;
    m_p1.id = m_p2.id = id;
    m_schema_idx = schema_id;
    if (allocate_api_param(&m_p1))
    {
        printf(
            "in openssl_checker::SetupParams() Parameter allocation failure - "
            "p1 of api %d (%s)\n",
            m_api_id,
            GetApiName((int)m_schema_idx));
        goto cleanup;
    }
    // randomize ctx1 and copy to ctx2
    randomize_api_param(&m_p1);
    copy_api_param(&m_p2, &m_p1);
    return 0;
cleanup:
    return 1;
}

const char* CSchemaChecker::GetApiName(int schema_id)
{
    if (!m_schema)
        return NULL;
    t_openssl_schema* api_schema = &m_schema[schema_id];
    return api_schema->api_name;
}

int CSchemaChecker::allocate_varlen(
    openssl_api_param* p,
    int varlen_index,
    int param_index,
    uint64_t type)
{
    size_t len = 0;

    if (m_varlen_values[varlen_index] == 0xFFFF)
    {
        len = (uint32_t)rand();
        OverideRandomizedValue(
            m_api_id,
            (uint32_t)param_index,
            type,
            0,
            (unsigned char*)&len,
            sizeof(len));
        m_varlen_values[varlen_index] = (uint32_t)len;
    }
    else
        len = m_varlen_values[varlen_index];
    p->p[param_index] = new (std::nothrow) char[len];
    if (!p->p[param_index])
    {
        printf(
            "Error: allocating %d bytes for paramter %d in "
            "openssl_checker::allocate_api_param of api %d (%s)\n",
            (int)len,
            param_index,
            m_api_id,
            "apiname");
        return 1;
    }
    return (int)len;
}

int CSchemaChecker::allocate_api_param(openssl_api_param* p)
{
    uint64_t type;
    size_t len;

    memset(p, 0, sizeof(*p));
    for (uint i = 0; i < MAX_VAR_LEN_VALUES; i++)
        m_varlen_values[i] = 0xFFFF;
    if (!m_schema)
        return 0;
    t_openssl_schema* api_schema = &m_schema[m_schema_idx];
    p->id = m_api_id;
    for (int i = 0; i < OPENSSL_MAX_PARAMETER_COUNT; i++)
    {
        type = api_schema->type[i];
        if (!SSL_VALID(type))
            break;

        if (SSL_FIXLEN(type))
        {
            len = api_schema->length[i];
            p->p[i] = new (std::nothrow) char[len];

            if (!p->p[i])
            {
                printf(
                    "Error: allocating %zu bytes for paramter %d in "
                    "openssl_checker::allocate_api_param of api %d (%s)\n",
                    len,
                    i,
                    m_api_id,
                    "apiname");
                return 1;
            }
        }
        else if (SSL_VARLEN_X(type))
        {
            len = (uint32_t)allocate_varlen(p, SSL_WHICH_VARLEN(type), i, type);
        }
    }
    int check_duplicate_slen[MAX_VAR_LEN_VALUES] = {0};
    for (int i = 0; i < OPENSSL_MAX_PARAMETER_COUNT; i++)
    {
        type = api_schema->type[i];
        if (!SSL_VALID(type))
            break;
        if (SSL_LEN_X(type))
        {
            int which_len = SSL_WHICH_LEN(type);
            check_duplicate_slen[which_len]++;
            uint len = m_varlen_values[which_len];
            *((size_t*)&(p->p[i])) = len;
        }
    }
    for (uint i = 0; i < MAX_VAR_LEN_VALUES; i++)
        if (check_duplicate_slen[i] > 1)
        {
            printf(
                "\n\n\napi %d (%s) ERROR in schema definition. Cannot use more "
                "than one S_LEN or S_LEN2\n",
                m_api_id,
                "apiname");
            exit(-1);
        }
    return 0;
}

int CSchemaChecker::free_api_param(openssl_api_param* p)
{
    // for 1 api - free params
    if (!m_schema)
        return 0;
    t_openssl_schema* api_schema = &m_schema[m_schema_idx];

    uint64_t type;

    for (int i = 0; i < OPENSSL_MAX_PARAMETER_COUNT; i++)
    {
        if (!p->p[i])
            return 1;

        type = api_schema->type[i];
        if (!SSL_VALID(type))
            break;

        if (SSL_FIXLEN(type) || SSL_VARLEN_X(type))
        {
            delete[] p->p[i];
            p->p[i] = nullptr;
        }
    }
    return 0;
}

int compare_evp_cipher_ctx_struct(char* p1, char* p2, size_t len, int fips)
{
    EVP_CIPHER_CTX* b1 = (EVP_CIPHER_CTX*)p1;
    EVP_CIPHER_CTX* b2 = (EVP_CIPHER_CTX*)p2;
    len = 0;
    fips = 0;
    if ((b1->encrypt != b2->encrypt) || (b1->buf_len != b2->buf_len) ||
        (b1->num != b2->num) || (b1->key_len != b2->key_len) ||
        (b1->flags != b2->flags) || (b1->final_used != b2->final_used) ||
        (b1->block_mask != b2->block_mask))
    {
        return 1;
    }
    return 0;
}

int compare_evp_md(char* p1, char* p2, size_t len, int fips)
{
    EVP_MD* b1 = (EVP_MD*)p1;
    EVP_MD* b2 = (EVP_MD*)p2;
    len = 0;
    fips = 0;
    if (!b1 && !b2)
        return 1;

    if (!b1 || !b2)
        return 0;

    if (b1->type != b2->type)
        return 1;
    if (b1->pkey_type != b2->pkey_type)
        return 1;
    if (b1->md_size != b2->md_size)
        return 1;
    if (b1->flags != b2->flags)
        return 1;
    if (b1->block_size != b2->block_size)
        return 1;
    if (b1->ctx_size != b2->ctx_size)
        return 1;
    return 0;
}

int compare_evp_md_ctx(char* p1, char* p2, size_t len, int fips)
{
    EVP_MD_CTX* b1 = (EVP_MD_CTX*)p1;
    EVP_MD_CTX* b2 = (EVP_MD_CTX*)p2;
    len = 0;
    fips = 0;

    if (!p1 && !p2)
        return 0;

    if (!p1 || !p2)
        return 1;

    if (b1->flags != b2->flags)
        return 1;

    return 0;
}

int CSchemaChecker::CleanUpParams()
{
    int ret = 0;
    ret = free_api_param(&m_p1);
    ret = free_api_param(&m_p2);
    return 0;
}
