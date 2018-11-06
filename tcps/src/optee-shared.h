#include <sgx.h>
#include <sgx_edger8r.h>
#include <openenclave/host.h>
#include <openenclave/edger8r/host.h>
#include "oeresult.h"

typedef sgx_status_t (SGX_CDECL * optee_ocall_t)(void* pms);

/* This is actually not a hard limit since we never use it to actually
 * allocate any space.  As long as the caller passes a valid number,
 * the "maximum" is ignored.  It's only used by the debugger.
 */
#define MAX_OCALLS 256

typedef struct {
    size_t nr_ocall;
    optee_ocall_t func_addr[MAX_OCALLS];
} optee_ocall_table_t;

typedef struct {
    size_t nr_ocall;
    const oe_ocall_func_t* call_addr;
} ocall_table_v2_t;

extern ocall_table_v2_t g_ocall_table_v2;
