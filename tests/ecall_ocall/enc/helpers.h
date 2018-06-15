// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

// TLS wrapper for a bit of syntactic sugar, in absence of thread_local
// support.
struct TLSWrapper
{
    TLSWrapper()
    {
        if (oe_thread_key_create(&m_key, NULL))
        {
            throw std::logic_error("oe_thread_key_create() failed");
        }
    }
    unsigned GetU() const
    {
        return (unsigned)(uintptr_t)oe_thread_get_specific(m_key);
    }

    void Set(unsigned Value)
    {
        oe_thread_set_specific(m_key, (void*)(uintptr_t)Value);
    }

  private:
    oe_thread_key_t m_key;
};
