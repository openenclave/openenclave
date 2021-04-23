// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// #include <algorithm>
#include <dirent.h>
#include <ftw.h>
#include <unistd.h>
#include <cstring>
#include <mutex>

static std::string g_cache_dirname = "";
static std::mutex cache_directory_lock;

static constexpr size_t CACHE_LOCATIONS = 5;
static const char* cache_locations[CACHE_LOCATIONS];

static void load_cache_locations()
{
    cache_locations[0] = ::getenv("AZDCAP_CACHE");
    cache_locations[1] = ::getenv("XDG_CACHE_HOME");
    cache_locations[2] = ::getenv("HOME");
    cache_locations[3] = ::getenv("TMPDIR");

    // The fallback location isn't an environment variable
    cache_locations[4] = "/tmp/";
}

static void init_callback()
{
    load_cache_locations();
    const std::string application_name("/.az-dcap-client/");
    std::string dirname;
    std::string all_locations;

    // Try the cache locations in order
    for (auto& cache_location : cache_locations)
    {
        if (cache_location != 0 && strcmp(cache_location, "") != 0)
        {
            dirname = cache_location + application_name;
            if (access(dirname.c_str(), F_OK) != -1)
            {
                g_cache_dirname = dirname;
                return;
            }
        }
    }

    // Collect all of the environment variables for the error message
    std::string environment_variable_list;
    for (size_t i = 0; i < CACHE_LOCATIONS - 1; ++i)
    {
        environment_variable_list += cache_locations[i];
        if (i != CACHE_LOCATIONS - 2)
        {
            environment_variable_list += ",";
        }
    }

    throw std::runtime_error(
        "No cache location was found. Please define one of the following "
        "environment variables to enable caching: " +
        environment_variable_list);
}

static void init()
{
    std::lock_guard<std::mutex> lock(cache_directory_lock);
    if (g_cache_dirname == "")
    {
        init_callback();
    }
}

static int delete_path(
    const char* fpath,
    const struct stat*,
    int typeflag,
    struct FTW* ftwbuf)
{
    if (ftwbuf->level == 0)
    {
        // do not delete the root directory of the cache
        return 0;
    }

    switch (typeflag)
    {
        case FTW_SL:
        case FTW_SLN:
        case FTW_F:
            return unlink(fpath);

        case FTW_DP:
            return rmdir(fpath);

        case FTW_D:
            errno = ENOTSUP;
            return -1;

        case FTW_DNR:
        case FTW_NS:
            errno = EACCES;
            return -1;

        default:
            errno = EINVAL;
            return -1;
    }
}

int local_cache_clear()
{
    init();

    std::lock_guard<std::mutex> lock(cache_directory_lock);
    constexpr int MAX_FDS = 4;
    int rc = nftw(g_cache_dirname.c_str(), delete_path, MAX_FDS, FTW_DEPTH);

    return rc;
}
