// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _DOX2MD_UTILS_H
#define _DOX2MD_UTILS_H

#include <string>

inline std::string basename(const std::string& name)
{
    size_t pos = name.rfind('/');

    if (pos == std::string::npos)
        return name;

    return name.substr(pos + 1);
}

inline std::string dirname(const std::string& name)
{
    size_t pos = name.rfind('/');

    if (pos == std::string::npos)
        return ".";

    return name.substr(0, pos);
}

inline std::string stripext(const std::string& name)
{
    size_t dot = name.rfind('.');

    if (dot == std::string::npos)
        return name;

    size_t slash = name.rfind('/');

    if (slash != std::string::npos && slash > dot)
        return name;

    return name.substr(0, dot);
}

#endif /* _DOX2MD_UTILS_H */
