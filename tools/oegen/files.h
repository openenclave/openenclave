// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCGEN_FILES_H
#define _ENCGEN_FILES_H

#include <stddef.h>
#include <vector>

int LoadFile(const char* path, size_t extra_bytes, void** data, size_t* size);

int LoadFile(const char* path, size_t extra_bytes, std::vector<char>& v);

#endif /* _ENCGEN_FILES_H */
