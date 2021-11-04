// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/defs.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/types.h>

#define PAGE_FAULT_HANDLER_STACK_SIZE 8192
#define PAGE_SIZE 4096
#define STACK_PAGE_NUMBER 1024
#define STACK_SIZE (STACK_PAGE_NUMBER * PAGE_SIZE)

OE_EXTERNC_BEGIN

void* td_to_tcs(const oe_sgx_td_t* td);
void get_stack(void** stack, uint64_t* stack_size);
int initialize_page_fault_handler_stack(void** stack, uint64_t* stack_size);
void cleaup_page_fault_handler_stack(void** stack, uint64_t* stack_size);

OE_EXTERNC_END
