// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

uint32_t calculate_crc32c(
    uint32_t Crc32c,
    const void* Buffer,
    unsigned int Length);

// Convenience C++ wrapper class
struct Crc32
{
    Crc32(unsigned Value) : m_Crc(Value)
    {
    }

    uint32_t Extend(const void* Buffer, unsigned Length)
    {
        m_Crc = calculate_crc32c(m_Crc, Buffer, Length);
        return m_Crc;
    }

    template <class T>
    uint32_t operator()(const T& Value)
    {
        return Extend(&Value, sizeof(T));
    }

    uint32_t operator()() const
    {
        return m_Crc;
    }

  private:
    uint32_t m_Crc;
};
