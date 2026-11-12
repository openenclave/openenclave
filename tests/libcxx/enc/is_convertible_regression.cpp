// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Exercise the patched fallback even when Clang provides a builtin trait.
#define _LIBCPP_USE_IS_CONVERTIBLE_FALLBACK
#include <type_traits>

namespace
{
struct Implicit
{
    operator int() const;
};
struct Explicit
{
    explicit operator int() const;
};
struct Base
{
};
struct Derived : Base
{
};
using Array = int[3];
using Function = int();

static_assert(std::is_convertible<int, double>::value, "arithmetic conversion");
static_assert(std::is_convertible<Implicit, int>::value, "implicit conversion");
static_assert(
    !std::is_convertible<Explicit, int>::value,
    "explicit conversion");
static_assert(std::is_convertible<void, void>::value, "void to void");
static_assert(!std::is_convertible<int, void>::value, "non-void to void");
static_assert(!std::is_convertible<void, int>::value, "void to non-void");
static_assert(std::is_convertible<Derived*, Base*>::value, "derived pointer");
static_assert(!std::is_convertible<Base*, Derived*>::value, "base pointer");
static_assert(std::is_convertible<Array&, int*>::value, "array decay");
static_assert(!std::is_convertible<int*, Array>::value, "array destination");
static_assert(
    std::is_convertible<Function&, Function*>::value,
    "function decay");
static_assert(
    !std::is_convertible<Function*, Function>::value,
    "function destination");
static_assert(std::is_convertible<int&, const int&>::value, "const reference");
static_assert(
    !std::is_convertible<const int&, int&>::value,
    "mutable reference");
} // namespace

int main()
{
    return 0;
}
