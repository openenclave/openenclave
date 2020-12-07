// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "include_openssl.h"
#include "string.h"

#define O_ENCLAVE 0
#define O_NATIVE 1

#define RD_BUFF_SIZE (1 << 20)

struct random_buffer
{
    char* buffer;
    int first;
    size_t size;
    size_t native_index;
    size_t enclave_index;
    int delta;
    unsigned int tid;
};

extern "C" int _set_random_buffer(int, void*);

#include "openssl_schema.h"

t_openssl_schema* get_digest_schema();
uint get_digest_schema_length();

class CSchemaChecker
{
  public:
    CSchemaChecker(t_openssl_schema* schema, uint schema_size);
    virtual ~CSchemaChecker();

    // random buffer methods
    int initialize_random_buffer(bool native);
    void RewindRandomBuffer();
    int UnsetRandomBuffers();
    int SetRandomBuffers();
    int DisableRandomInjection();
    int EnablebackEnclaveRandomInjection();

    // schema methods
    virtual int allocate_api_param(openssl_api_param* p);
    virtual int free_api_param(openssl_api_param* p);
    virtual void randomize_api_param(openssl_api_param* p);
    virtual void copy_api_param(openssl_api_param* p2, openssl_api_param* p1);
    virtual int check_openssl(openssl_api_param* p1, openssl_api_param* p2);
    virtual int SetupParams(openssl_api_id id, uint schema_id);
    virtual int CleanUpParams();
    const char* GetApiName(int schema_id);
    openssl_api_id GetApiId(int idx);
    virtual void OverideRandomizedValue(
        openssl_api_id id,
        uint param_number,
        uint64_t type,
        uint origin,
        unsigned char* buf,
        uint buflen)
    {
        if (SSL_VARLEN(type) && (buflen == sizeof(size_t)))
        {
            size_t v = *(size_t*)buf;
            v = v % 0x10000;
            if (v == 0)
                v = 1;
            *(size_t*)buf = v;
        }
    }

    openssl_api_param m_p1, m_p2;

  protected:
    int allocate_varlen(
        openssl_api_param* p,
        int varlen_index,
        int param_index,
        uint64_t type);

    openssl_api_id m_api_id;
    t_openssl_schema* m_schema;
    uint m_schema_num_apis;
    bool m_own_enclave;
    uint thread_number;
    uint m_schema_idx;
    uint m_varlen_values[MAX_VAR_LEN_VALUES];
};
