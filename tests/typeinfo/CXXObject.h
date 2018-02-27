#ifndef _CXXOBJECT_H
#define _CXXOBJECT_H

#include <new>
#include "typeinfo_u.h"

struct CXXObject : public Object
{
    CXXObject()
    {
        memset(this, 0, sizeof(*this));
    }

    CXXObject(size_t id_, const char* name_)
    {
        id = id_;
        name = strdup(name_);
    }

    ~CXXObject()
    {
        free(name);
        memset(this, 0, sizeof(*this));
    }

    void* operator new(size_t size)
    {
        return malloc(size);
    }

    void operator delete(void* ptr)
    {
        return free(ptr);
    }
};

#endif /* _CXXOBJECT_H */
