// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/defs.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/types.h>

#define EXCEPTION_HANDLER_STACK_SIZE 8192
#define PAGE_SIZE 4096
#define STACK_PAGE_NUMBER 1024
#define STACK_SIZE (STACK_PAGE_NUMBER * PAGE_SIZE)

OE_EXTERNC_BEGIN

bool oe_sgx_set_td_exception_handler_stack(void* stack, uint64_t size);
void* td_to_tcs(const oe_sgx_td_t* td);
int initialize_exception_handler_stack(
    void** stack,
    uint64_t* stack_size,
    int use_exception_handler_stack);
void cleaup_exception_handler_stack(
    void** stack,
    uint64_t* stack_size,
    int use_exception_handler_stack);

OE_EXTERNC_END
