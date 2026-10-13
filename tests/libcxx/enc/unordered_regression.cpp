// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace
{
struct CollisionHash
{
    std::size_t operator()(int) const
    {
        return 1;
    }
};

template <class Hash>
bool test_insertions()
{
    std::unordered_map<int, std::string, Hash> values;
    values.max_load_factor(0.5f);
    const auto first = values.emplace(7, "first");
    if (!first.second || first.first->second != "first")
        return false;
    const auto duplicate = values.emplace(7, "replacement");
    if (duplicate.second || duplicate.first->second != "first" ||
        values.size() != 1)
        return false;

    const auto initial_buckets = values.bucket_count();
    for (int i = 0; i < 100; ++i)
        values[i] = std::to_string(i);
    if (values.size() != 100 || values.bucket_count() <= initial_buckets)
        return false;
    values.reserve(400);
    values.rehash(1024);
    for (int i = 0; i < 100; ++i)
    {
        const auto found = values.find(i);
        if (found == values.end() || found->second != std::to_string(i))
            return false;
    }

    auto moved = std::move(values);
    // A moved-from container remains valid, but its contents are unspecified.
    values.clear();
    if (!values.emplace(5, "reused").second || values.at(5) != "reused")
        return false;
    moved.clear();
    moved.rehash(0);
    if (!moved.emplace(9, "reset").second || moved.at(9) != "reset")
        return false;

    std::unordered_set<int, Hash> keys;
    for (int i = 0; i < 100; ++i)
    {
        if (!keys.emplace(i).second || keys.emplace(i).second)
            return false;
    }
    keys.rehash(512);
    for (int i = 0; i < 100; ++i)
    {
        if (keys.count(i) != 1)
            return false;
    }
    return true;
}
} // namespace

int main()
{
    if (!test_insertions<std::hash<int>>() || !test_insertions<CollisionHash>())
        return 1;

    std::unordered_map<std::string, int> names;
    if (!names.emplace("key", 42).second || names.emplace("key", 0).second ||
        names.at("key") != 42)
        return 2;
#if __cplusplus >= 201703L
    if (!names.try_emplace("other", 3).second ||
        names.try_emplace("other", 4).second || names.at("other") != 3)
        return 3;
#endif
    return 0;
}