// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

// TLS wrapper for a bit of syntactic sugar, in absence of thread_local
// support.
class tls_wrapper
{
  public:
    tls_wrapper()
    {
        if (oe_thread_key_create(&m_key, NULL))
        {
            throw std::logic_error("oe_thread_key_create() failed");
        }
    }
    unsigned get_u() const
    {
        return static_cast<unsigned>(
            reinterpret_cast<uintptr_t>(oe_thread_getspecific(m_key)));
    }

    void set(unsigned value)
    {
        oe_thread_setspecific(
            m_key, reinterpret_cast<void*>(static_cast<uintptr_t>(value)));
    }

  private:
    oe_thread_key_t m_key;
};
