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

    template <class T1, class... T2>
    uint32_t operator()(const T1& Value1, const T2&... Value2)
    {
        Extend(&Value1, sizeof(T1));
        return (*this)(Value2...);
    }

    uint32_t operator()() const
    {
        return m_Crc;
    }

    template <class... T1>
    static uint32_t Hash(unsigned Start, const T1&... Value1)
    {
        Crc32 crc(Start);
        return crc(Value1...);
    }

  private:
    uint32_t m_Crc;
};
