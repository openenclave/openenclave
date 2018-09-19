// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "objects.h"
#include <cstdio>
#include <cstring>

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

static void _DumpQualifiers(unsigned int flags, const QualifierValues& values)
{
    unsigned int mask = 0;
    mask |= FLAG_ECALL;
    mask |= FLAG_OCALL;
    mask |= FLAG_IN;
    mask |= FLAG_OUT;
    mask |= FLAG_UNCHECKED;
    mask |= FLAG_COUNT;

    if (flags & mask)
    {
        size_t count = 0;

        printf("[");

        if (flags & FLAG_ECALL)
        {
            printf("ecall");
            count++;
        }

        if (flags & FLAG_OCALL)
        {
            if (count)
                printf(", ");
            printf("ocall");
            count++;
        }

        if (flags & FLAG_IN)
        {
            if (count)
                printf(", ");
            printf("in");
            count++;
        }

        if (flags & FLAG_OUT)
        {
            if (count)
                printf(", ");
            printf("out");
            count++;
        }

        if (flags & FLAG_OPT)
        {
            if (count)
                printf(", ");
            printf("opt");
            count++;
        }

        if (flags & FLAG_UNCHECKED)
        {
            if (count)
                printf(", ");
            printf("unchecked");
            count++;
        }

        if (flags & FLAG_COUNT)
        {
            if (count)
                printf(", ");
            printf("count=%s", values.count.c_str());
            count++;
        }

        printf("] ");
    }
}

/*
**==============================================================================
**
** struct ReturnType
**
**==============================================================================
*/

void ReturnType::Dump() const
{
    _DumpQualifiers(flags, qvals);

    if (flags & FLAG_CONST)
        printf("const ");

    if (flags & FLAG_STRUCT)
        printf("struct ");

    printf("%s ", type.c_str());

    if (flags & FLAG_PTR)
        printf("*");
}

/*
**==============================================================================
**
** struct Param
**
**==============================================================================
*/

void Param::Dump() const
{
    _DumpQualifiers(flags, qvals);

    if (flags & FLAG_CONST)
        printf("const ");

    if (flags & FLAG_STRUCT)
        printf("struct ");

    printf("%s ", type.c_str());

    if (flags & FLAG_PTR)
        printf("*");

    printf("%s", name.c_str());
}

/*
**==============================================================================
**
** struct Field
**
**==============================================================================
*/

void Field::Dump() const
{
    _DumpQualifiers(flags, qvals);

    if (flags & FLAG_CONST)
        printf("const ");

    if (flags & FLAG_STRUCT)
        printf("struct ");

    printf("%s ", type.c_str());

    if (flags & FLAG_PTR)
        printf("*");

    printf("%s", name.c_str());
}

/*
**==============================================================================
**
** class Object
**
**==============================================================================
*/

Object::~Object()
{
}

/*
**==============================================================================
**
** class Function
**
**==============================================================================
*/

Function::~Function()
{
}

void Function::Dump() const
{
    printf("function ");

    returnType.Dump();

    printf("%s(\n", name.c_str());

    for (size_t i = 0; i < params.size(); i++)
    {
        printf("    ");

        params[i].Dump();

        if (i + 1 == params.size())
            printf(");\n");
        else
            printf(",\n");
    }

    printf("\n");
}

size_t Function::FindParam(const std::string& name) const
{
    for (size_t i = 0; i < params.size(); i++)
    {
        if (params[i].name == name)
            return i;
    }

    return (size_t)-1;
}

/*
**==============================================================================
**
** class Struct
**
**==============================================================================
*/

Struct::~Struct()
{
}

void Struct::Dump() const
{
    printf("struct ");

    printf("%s\n", name.c_str());
    printf("{\n");

    for (size_t i = 0; i < fields.size(); i++)
    {
        printf("    ");
        fields[i].Dump();
        printf(";;\n");
    }

    printf("}\n");
    printf("\n");
}

size_t Struct::FindField(const std::string& name) const
{
    for (size_t i = 0; i < fields.size(); i++)
    {
        if (fields[i].name == name)
            return i;
    }

    return (size_t)-1;
}

/*
**==============================================================================
**
** class Verbatim
**
**==============================================================================
*/

Verbatim::~Verbatim()
{
}

void Verbatim::Dump() const
{
    printf("verbatim \"%s\"\n\n", filename.c_str());
}
