// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

// TLS wrapper for a bit of syntactic sugar, in absence of thread_local
// support.
struct TLSWrapper
{
    TLSWrapper()
    {
        if (OE_ThreadKeyCreate(&m_Key, NULL))
        {
            throw std::logic_error("OE_ThreadKeyCreate() failed");
        }
    }
    unsigned GetU() const
    {
        return (unsigned)(uintptr_t)OE_ThreadGetSpecific(m_Key);
    }

    void Set(unsigned Value)
    {
        OE_ThreadSetSpecific(m_Key, (void*)(uintptr_t)Value);
    }

  private:
    OE_ThreadKey m_Key;
};
