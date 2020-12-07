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
    m_schema_index = 0;
    m_schema_api_count = schema_size;

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
    size_t length;
    char* buffer;
    if (!m_schema)
        return;

    t_openssl_schema* api_schema = &m_schema[m_schema_index];
    for (int i = 0; i < OPENSSL_MAX_PARAMETER_COUNT; i++)
    {
        buffer = p->p[i];
        type = api_schema->type[i];
        if (!SSL_VALID(type))
            break;

        if (SSL_FIXLEN(type))
        {
            length = api_schema->length[i];
            for (size_t j = 0; j < length; j++)
                buffer[j] = (char)(rand());
            OverideRandomizedValue(type, (unsigned char*)buffer, (uint)length);
        }
        else if (SSL_VARLEN_X(type))
        {
            length = (size_t)m_varlen_values[SSL_WHICH_VARLEN(type)];
            for (size_t j = 0; j < length; j++)
                buffer[j] = (char)(rand());
            OverideRandomizedValue(type, (unsigned char*)buffer, (uint)length);
        }
    }
}

void CSchemaChecker::copy_api_param(
    openssl_api_param* p2,
    openssl_api_param* p1)
{
    uint64_t type;
    size_t length;

    if (!m_schema)
        return;
    t_openssl_schema* api_schema = &m_schema[m_schema_index];

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
            length = api_schema->length[i];

            p2->p[i] = new (std::nothrow) char[length];
            b2 = p2->p[i];
            assert(b2);
            memcpy(b2, b1, length);
        }
        else if (SSL_VARLEN_X(type))
        {
            length = (size_t)m_varlen_values[SSL_WHICH_VARLEN(type)];
            p2->p[i] = new (std::nothrow) char[length];
            assert(NULL != p2->p[i]);
            b2 = p2->p[i];
            memcpy(b2, b1, length);
        }
        else if (SSL_LEN_X(type))
        {
            p2->p[i] = p1->p[i];
        }
    }
}

int CSchemaChecker::SetupParams(openssl_api_id id, uint schema_id)
{
    // per 1 api
    m_api_id = id;
    m_p1.id = m_p2.id = id;
    m_schema_index = schema_id;
    if (allocate_api_param(&m_p1))
    {
        printf(
            "in openssl_checker::SetupParams() Parameter allocation failure - "
            "p1 of api %d (%s)\n",
            m_api_id,
            GetApiName((int)m_schema_index));
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
    size_t length = 0;

    if (m_varlen_values[varlen_index] == 0xFFFF)
    {
        length = (uint32_t)rand();
        OverideRandomizedValue(type, (unsigned char*)&length, sizeof(length));
        m_varlen_values[varlen_index] = (uint32_t)length;
    }
    else
        length = m_varlen_values[varlen_index];
    p->p[param_index] = new (std::nothrow) char[length];
    if (!p->p[param_index])
    {
        printf(
            "Error: allocating %d bytes for paramter %d in "
            "openssl_checker::allocate_api_param of api %d (%s)\n",
            (int)length,
            param_index,
            m_api_id,
            "apiname");
        return 1;
    }
    return (int)length;
}

int CSchemaChecker::allocate_api_param(openssl_api_param* p)
{
    uint64_t type;
    size_t length;

    memset(p, 0, sizeof(*p));
    for (uint i = 0; i < MAX_VAR_LEN_VALUES; i++)
        m_varlen_values[i] = 0xFFFF;
    if (!m_schema)
        return 0;
    t_openssl_schema* api_schema = &m_schema[m_schema_index];
    p->id = m_api_id;
    for (int i = 0; i < OPENSSL_MAX_PARAMETER_COUNT; i++)
    {
        type = api_schema->type[i];
        if (!SSL_VALID(type))
            break;

        if (SSL_FIXLEN(type))
        {
            length = api_schema->length[i];
            p->p[i] = new (std::nothrow) char[length];

            if (!p->p[i])
            {
                printf(
                    "Error: allocating %zu bytes for paramter %d in "
                    "openssl_checker::allocate_api_param of api %d (%s)\n",
                    length,
                    i,
                    m_api_id,
                    "apiname");
                return 1;
            }
        }
        else if (SSL_VARLEN_X(type))
        {
            length =
                (uint32_t)allocate_varlen(p, SSL_WHICH_VARLEN(type), i, type);
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
            uint length = m_varlen_values[which_len];
            *((size_t*)&(p->p[i])) = length;
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
    t_openssl_schema* api_schema = &m_schema[m_schema_index];

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

int CSchemaChecker::CleanUpParams()
{
    int return_value = 0;
    return_value |= free_api_param(&m_p1);
    return_value |= free_api_param(&m_p2);
    return return_value;
}
