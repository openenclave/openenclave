#ifndef _ENCGEN_FILES_H
#define _ENCGEN_FILES_H

#include <stddef.h>
#include <vector>

int LoadFile(
    const char* path,
    size_t extraBytes,
    void** data,
    size_t* size);

int LoadFile(
    const char* path,
    size_t extraBytes,
    std::vector<char>& v);

#endif /* _ENCGEN_FILES_H */
