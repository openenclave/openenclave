// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>

#include "VectorException_t.h"

#define OE_UD2_OPCODE 0x0b0f

void call_illegal_instruction()
{
    asm volatile("ud2;");
}

uint64_t continuation_callback(oe_exception_record_t* record)
{
    record->context->rip += 2;

    // OCalls can be make in the continuation callback
    host_set_exception_handled();

    return 0;
}

uint64_t handler(oe_exception_record_t* record)
{
    if (record->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        if (*((uint16_t*)record->context->rip) == OE_UD2_OPCODE)
        {
            record->continuation_callback = continuation_callback;
            return OE_EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return OE_EXCEPTION_CONTINUE_SEARCH;
}

void enc_test_continuation_callback()
{
    oe_add_vectored_exception_handler(true, handler);
    call_illegal_instruction();
    oe_remove_vectored_exception_handler(handler);
}
