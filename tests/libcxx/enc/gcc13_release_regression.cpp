// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <array>
#include <functional>
#include <regex>
#include <stdexcept>
#include <string>
#include <utility>

namespace
{
template <class T>
struct StatefulAllocator : std::allocator<T>
{
    int* allocations;
    bool fail;

    template <class U>
    struct rebind
    {
        using other = StatefulAllocator<U>;
    };

    StatefulAllocator(int* count, bool should_fail)
        : allocations(count), fail(should_fail)
    {
    }

    T* allocate(std::size_t size)
    {
        if (fail)
            throw std::bad_alloc();
        ++*allocations;
        return std::allocator<T>::allocate(size);
    }

    void deallocate(T* pointer, std::size_t size)
    {
        --*allocations;
        std::allocator<T>::deallocate(pointer, size);
    }
};

struct SmallCallable
{
    int* destroyed;

    int operator()() const
    {
        return 42;
    }

    ~SmallCallable()
    {
        ++*destroyed;
    }
};

struct LargeCallable
{
    std::array<int, 128> values;
    int* destroyed;

    int operator()() const
    {
        return values[0];
    }

    ~LargeCallable()
    {
        ++*destroyed;
    }
};
} // namespace

int main()
{
    // The default state is moved before regex assigns the starting position.
    std::__state<char> state;
    if (state.__at_first_)
        return 1;

    const char short_text[] = "short";
    const std::string short_range(short_text, short_text + 5);
    const std::string empty_range(short_text, short_text);
    const std::string long_text(256, 'x');
    const std::string long_range(long_text.begin(), long_text.end());
    if (short_range != "short" || !empty_range.empty() ||
        long_range != long_text)
        return 10;

    int allocations = 0;
    using Allocator = StatefulAllocator<char>;
    using AllocatedString =
        std::basic_string<char, std::char_traits<char>, Allocator>;
    {
        const StatefulAllocator<char> allocator(&allocations, false);
        const AllocatedString value(
            long_text.begin(), long_text.end(), allocator);
        if (value.size() != long_text.size() || value.front() != 'x' ||
            value.back() != 'x' || value.c_str()[value.size()] != '\0' ||
            value.get_allocator().allocations != &allocations ||
            allocations != 1)
            return 11;
    }
    if (allocations != 0)
        return 12;
    try
    {
        const AllocatedString value(
            long_text.begin(),
            long_text.end(),
            StatefulAllocator<char>(&allocations, true));
        return 13;
    }
    catch (const std::bad_alloc&)
    {
        if (allocations != 0)
            return 14;
    }

    const std::string text("abc123");
    std::smatch match;
    const std::regex pattern("([[:alpha:]]+)([[:digit:]]+)");
    if (!std::regex_match(text, match, pattern) || match[1] != "abc" ||
        match[2] != "123")
        return 2;
    if (std::regex_replace(text, pattern, "$2-$1") != "123-abc")
        return 3;
    if (!std::regex_search(text, std::regex("123")) ||
        std::regex_match(text, std::regex("[[:alpha:]]+")))
        return 4;

    std::regex_traits<char> traits;
    const char letters[] = "abc";
    const char classname[] = "alpha";
    const char collatename[] = "a";
    if (traits.transform(letters, letters + 3).empty())
        return 5;
    // libc++ 10's primary transform accepts one-character C-locale keys.
    if (traits.transform_primary(letters, letters + 1) != "a")
        return 20;
    if (traits.lookup_collatename(collatename, collatename + 1) != "a")
        return 21;
    if (!traits.isctype('a', traits.lookup_classname(classname, classname + 5)))
        return 22;

    std::function<int()> empty;
    std::function<int()> small = [] { return 42; };
    auto moved_small = std::move(small);
    if (empty || moved_small() != 42)
        return 6;
    small = nullptr;
    moved_small = nullptr;

    int small_destroyed = 0;
    {
        SmallCallable callable{&small_destroyed};
        std::function<int()> value = callable;
        const int before_destruction = small_destroyed;
        {
            auto copy = value;
            if (copy() != 42)
                return 15;
        }
        if (small_destroyed != before_destruction + 1)
            return 16;
    }
    // Construction may destroy additional temporaries before these scopes exit.
    if (small_destroyed < 3)
        return 17;

    int destroyed = 0;
    {
        LargeCallable callable{{{7}}, &destroyed};
        std::function<int()> large = callable;
        auto copy = large;
        auto moved = std::move(large);
        if (copy() != 7 || moved() != 7)
            return 7;
        const int before_destruction = destroyed;
        {
            auto scoped_copy = copy;
            if (scoped_copy() != 7)
                return 18;
        }
        if (destroyed != before_destruction + 1)
            return 19;
        const int before_reset = destroyed;
        copy = nullptr;
        moved = nullptr;
        if (destroyed != before_reset + 2)
            return 8;
    }
    return destroyed >= 3 ? 0 : 9;
}
