#ifndef _OE_OBJECTS_H
#define _OE_OBJECTS_H

#include <string>
#include <vector>

// Type flags:
#define FLAG_STRUCT (1 << 0)
#define FLAG_CONST (1 << 1)
#define FLAG_PTR (1 << 2)
#define FLAG_ARRAY (1 << 3)

// Qualifier flags:
#define FLAG_ECALL (1 << 5)
#define FLAG_OCALL (1 << 6)
#define FLAG_IN (1 << 7)
#define FLAG_OUT (1 << 8)
#define FLAG_REF (1 << 9)
#define FLAG_UNCHECKED (1 << 10)
#define FLAG_COUNT (1 << 11)
#define FLAG_STRING (1 << 12)
#define FLAG_OPT (1 << 13)

struct QualifierValues
{
    std::string count;

    void Clear()
    {
        count.clear();
    }
};

struct ReturnType
{
    unsigned int flags;
    QualifierValues qvals;
    std::string type;
    std::string name;

    ReturnType() : flags(0), name("ret")
    {
    }

    void Clear()
    {
        flags = 0;
        qvals.Clear();
        type.clear();
    }

    void Dump() const;

    bool Empty() const
    {
        return type == "void" && !(flags & FLAG_PTR);
    }
};

struct Param
{
    unsigned int flags;
    QualifierValues qvals;
    std::string type;
    std::string name;
    unsigned int subscript;

    Param() : flags(0), subscript(0)
    {
    }

    void Clear()
    {
        flags = 0;
        qvals.Clear();
        type.clear();
        name.clear();
        subscript = 0;
    }

    // Whether this parameter may bear the [count=?] qualifier.
    bool IsPointer() const
    {
        if (!(flags & FLAG_PTR))
            return false;

        return true;
    }

    // Return true if this parameter has the right type to be the argument of
    // a [count=?] qualifier.
    bool IsCounter() const
    {
        return type == "size_t";
    }

    void Dump() const;
};

struct Field
{
    unsigned int flags;
    QualifierValues qvals;
    std::string type;
    std::string name;
    unsigned int subscript;

    Field() : flags(0), subscript(0)
    {
    }

    void Clear()
    {
        flags = 0;
        qvals.Clear();
        type.clear();
        name.clear();
        subscript = 0;
    }

    // Whether this parameter may bear the [count=?] qualifier.
    bool IsPointer() const
    {
        if (!(flags & FLAG_PTR))
            return false;

        return true;
    }

    // Return true if this field has the right type to be the argument of
    // a [count=?] qualifier.
    bool IsCounter() const
    {
        return type == "size_t";
    }

    void Dump() const;
};

class Object
{
  public:
    virtual ~Object();

    virtual void Dump() const = 0;
};

class Function : public Object
{
  public:
    std::string name;
    ReturnType returnType;
    std::vector<Param> params;

    virtual ~Function();

    virtual void Dump() const;

    void Clear()
    {
        name.clear();
        returnType.Clear();
        params.clear();
    }

    size_t FindParam(const std::string& name) const;
};

inline size_t FindParam(const std::vector<Param>& params, const std::string& name)
{
    for (size_t i = 0; i < params.size(); i++)
    {
        if (params[i].name == name)
            return i;
    }

    return (size_t)-1;
}

class Struct : public Object
{
  public:
    std::string name;
    std::vector<Field> fields;

    virtual ~Struct();

    virtual void Dump() const;

    void Clear()
    {
        name.clear();
        fields.clear();
    }

    size_t FindField(const std::string& name) const;
};

class Verbatim : public Object
{
  public:
    std::string filename;

    virtual ~Verbatim();

    virtual void Dump() const;
};

// Whether this parameter may bear the [out] qualifier.
inline bool Writable(unsigned int flags)
{
    if (!(flags & FLAG_PTR) && !(flags & FLAG_ARRAY))
        return false;

    // Cannot write an object through a const pointer:
    if (flags & FLAG_CONST)
        return false;

    return true;
}

#endif /* _OE_OBJECTS_H */
