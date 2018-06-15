// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "parser.h"
#include <climits>
#include <cstdlib>
#include <set>
#include "files.h"
#include "types.h"

using namespace std;

static set<string> _types;
static bool _initialize_types;

// #define HAVE_PTR_PTR

static int _add_type(unsigned int flags, const string& type)
{
    string full_type_name;

    if (flags & FLAG_STRUCT)
        full_type_name = "struct " + type;
    else
        full_type_name = type;

    if (_types.find(full_type_name) != _types.end())
        return -1;

    _types.insert(full_type_name);

    return 0;
}

static int _check_type(unsigned int flags, const string& type)
{
    if (!_initialize_types)
    {
        for (size_t i = 0; i < ntypes; i++)
            _types.insert(types[i].idl_name);

        _initialize_types = true;
    }

    string full_type_name;

    if (flags & FLAG_STRUCT)
        full_type_name = "struct " + type;
    else
        full_type_name = type;

    if (_types.find(full_type_name) == _types.end())
        return -1;

    return 0;
}

static bool _is_number(const string& s)
{
    for (size_t i = 0; i < s.size(); i++)
    {
        if (!isdigit(s[i]))
            return false;
    }

    return true;
}

static int _parse_qualifiers(
    Lexer& lexer,
    unsigned int& flags,
    QualifierValues& qvals)
{
    int rc = -1;
    Tok tok = TOK_ERR;

    flags = 0;

    while ((tok = lexer.Next()) > 0)
    {
        string ident;

        if (tok == TOK_CLOSE_BRACKET)
        {
            rc = 0;
            goto done;
        }
        else if (tok == TOK_IDENTIFIER)
        {
            ident = lexer.text;

            if (strcmp(lexer.text, "ecall") == 0)
                flags |= FLAG_ECALL;
            else if (strcmp(lexer.text, "ocall") == 0)
                flags |= FLAG_OCALL;
            else if (strcmp(lexer.text, "in") == 0)
                flags |= FLAG_IN;
            else if (strcmp(lexer.text, "out") == 0)
                flags |= FLAG_OUT;
            else if (strcmp(lexer.text, "inout") == 0)
                flags |= FLAG_IN | FLAG_OUT;
            else if (strcmp(lexer.text, "opt") == 0)
                flags |= FLAG_OPT;
            else if (strcmp(lexer.text, "ref") == 0)
                flags |= FLAG_REF;
            else if (strcmp(lexer.text, "unchecked") == 0)
                flags |= FLAG_UNCHECKED;
            else if (strcmp(lexer.text, "count") == 0)
                flags |= FLAG_COUNT;
            else if (strcmp(lexer.text, "one") == 0)
            {
                flags |= FLAG_COUNT;
                qvals.count = "1";
            }
            else if (strcmp(lexer.text, "string") == 0)
                flags |= FLAG_STRING;
            else
            {
                rc = -1;
                lexer.SetErr("unknown qualifier: %s\n", lexer.text);
                goto done;
            }
        }

        switch (tok = lexer.Next())
        {
            case TOK_EQUAL:
                goto parse_initializer;
            case TOK_COMMA:
                goto parse_comma;
            case TOK_CLOSE_BRACKET:
                goto parse_close_bracket;
            default:
                goto malformed_qualifier_list;
        }

    parse_initializer:

        switch ((tok = lexer.Next()))
        {
            case TOK_IDENTIFIER:
            {
                break;
            }
            case TOK_NUMBER:
            {
                break;
            }
            default:
            {
                lexer.SetErr("invalid qualifier initializer");
                rc = -1;
                goto done;
            }
        }

        if (ident == "count")
        {
            qvals.count = lexer.text;
        }
        else
        {
            lexer.SetErr("illegal qualifier initializer for %s", ident.c_str());
            rc = -1;
            goto done;
        }

        switch (tok = lexer.Next())
        {
            case TOK_COMMA:
                goto parse_comma;
            case TOK_CLOSE_BRACKET:
                goto parse_close_bracket;
            default:
                goto malformed_qualifier_list;
        }

    parse_comma:

        continue;

    parse_close_bracket:

        rc = 0;
        goto done;
    }

    lexer.SetErr("missing closing bracket");
    rc = -1;
    return rc;

malformed_qualifier_list:

    lexer.SetErr("malformed qualifier list");
    return rc;

done:

    return rc;
}

static int _check_qualifiers(
    Lexer& lexer,
    bool is_return_type,
    bool is_param,
    const string& name,
    unsigned int flags,
    const string& type)
{
    int rc = -1;

    // Check for present qualifiers:
    {
        if (flags & FLAG_ECALL)
        {
            if (!is_return_type)
            {
                lexer.SetErr("[ecall] illegal on '%s'", name.c_str());
                goto done;
            }

            if (flags & FLAG_OCALL)
            {
                lexer.SetErr("[ecall] and [ocall] are incompatible");
                goto done;
            }
        }

        if (flags & FLAG_OCALL)
        {
            if (!is_return_type)
            {
                lexer.SetErr("[ocall] illegal on '%s'", name.c_str());
                goto done;
            }
        }

        if (flags & FLAG_IN)
        {
            if (is_return_type)
            {
                lexer.SetErr("[in] illegal on '%s'", name.c_str());
                goto done;
            }
        }

        if (flags & FLAG_OUT)
        {
            if (is_return_type)
            {
                lexer.SetErr("[in] illegal on '%s'", name.c_str());
                goto done;
            }
            else
            {
                if (!Writable(flags))
                {
                    lexer.SetErr(
                        "[out] illegal on non-writable '%s'", name.c_str());
                    goto done;
                }
            }
        }

        if (flags & FLAG_UNCHECKED)
        {
            if (flags & FLAG_COUNT)
            {
                lexer.SetErr(
                    "[unchecked] and [count] are incompatible: '%s'",
                    name.c_str());
                goto done;
            }

            if (flags & FLAG_STRING)
            {
                lexer.SetErr(
                    "[unchecked] and [string] are incompatible: '%s'",
                    name.c_str());
                goto done;
            }
        }

        if (flags & FLAG_COUNT)
        {
            if (!(flags & FLAG_PTR))
            {
                lexer.SetErr(
                    "[count] only allowed on pointers: '%s'", name.c_str());
                goto done;
            }
        }

        if (flags & FLAG_STRING)
        {
            bool is_ptr = (flags & FLAG_PTR);
            bool is_char = type == "char" || type == "wchar_t";
            bool is_arr = (flags & FLAG_ARRAY);

            if (!is_char || (!is_ptr && !is_arr))
            {
                lexer.SetErr(
                    "[string] not allowed on this type: '%s'", name.c_str());
                goto done;
            }

            if (is_char && is_ptr && (flags & FLAG_OUT) && !(flags & FLAG_COUNT))
            {
                lexer.SetErr(
                    "[count] qualifier required here: '%s'", name.c_str());
                goto done;
            }
        }
    }

    // Check for missing qualifiers:
    {
        if (is_return_type && !(flags & FLAG_ECALL) && !(flags & FLAG_OCALL))
        {
            lexer.SetErr("need [ecall] or [ocall]: '%s'", name.c_str());
            goto done;
        }

        if (flags & FLAG_PTR)
        {
            if (!(flags & FLAG_UNCHECKED) && !(flags & FLAG_COUNT) &&
                !(flags & FLAG_STRING))
            {
                if (type == "char" || type == "wchar_t")
                {
                    lexer.SetErr(
                        "need [unchecked], [count] or [string]: '%s'",
                        name.c_str());
                }
                else
                {
                    lexer.SetErr(
                        "need [unchecked] or [count]: '%s'", name.c_str());
                }
                goto done;
            }
        }
    }

    // Reject reference qualifiers on non-parameters:
    if (!is_param && (flags & FLAG_REF))
    {
        lexer.SetErr("[ref] only valid on parameters: '%s'", name.c_str());
        goto done;
    }

    if ((flags & FLAG_REF) && (flags & FLAG_IN))
    {
        lexer.SetErr(
            "[ref] only valid on output parameters: '%s'", name.c_str());
        goto done;
    }

// Handle qualifiers on pointer-params and array-params:
#if 0
    if (is_param && (flags & FLAG_PTR || flags & FLAG_ARRAY))
#endif
    if (is_param && name.size()) // Ignore void:
    {
        if (!(flags & FLAG_IN || flags & FLAG_OUT))
        {
            lexer.SetErr("need [in] or [out] on parameter: '%s'", name.c_str());
            goto done;
        }
    }

    // Handle qualifiers on non-pointer-params and non-array-params:
    if (is_param && !(flags & FLAG_PTR || flags & FLAG_ARRAY))
    {
        if (flags & FLAG_OUT)
        {
            lexer.SetErr("[out] invalid on this type: '%s'", name.c_str());
            goto done;
        }
    }

    rc = 0;

done:
    return rc;
}

static int _parse_return_type(Lexer& lexer, ReturnType& x)
{
    int rc = -1;
    Tok tok = TOK_ERR;
    bool signed_type = false;
    bool unsigned_type = false;

    x.Clear();

    /* '[' ... ']' [const] [struct] [signed] type [*] name */

    switch (tok = lexer.Next())
    {
        case TOK_OPEN_BRACKET:
            goto parse_qualifiers;
        case TOK_CONST:
            goto parse_const;
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_qualifiers:

    if (_parse_qualifiers(lexer, x.flags, x.qvals) != 0)
        goto done;

    switch (tok = lexer.Next())
    {
        case TOK_CONST:
            goto parse_const;
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_const:

    x.flags |= FLAG_CONST;

    switch (tok = lexer.Next())
    {
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_struct:

    x.flags |= FLAG_STRUCT;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_signed:

    signed_type = true;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_unsigned:

    unsigned_type = true;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_type:

    if (signed_type)
        x.type = "signed " + string(lexer.text);
    else if (unsigned_type)
        x.type = "unsigned " + string(lexer.text);
    else
        x.type = string(lexer.text);

    switch (tok = lexer.Next())
    {
        case TOK_PTR:
            goto parse_ptr;
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_ptr:

    x.flags |= FLAG_PTR;

    switch (tok = lexer.Next())
    {
#ifdef HAVE_PTR_PTR
        case TOK_PTR:
            goto parse_ptr_ptr;
#endif /* HAVE_PTR_PTR */
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

#ifdef HAVE_PTR_PTR
parse_ptr_ptr:

    x.flags &= ~FLAG_PTR;
    x.flags |= FLAG_PTR_PTR;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }
#endif /* HAVE_PTR_PTR */

parse_name:

    goto check_qualifiers;

check_qualifiers:

    if (_check_qualifiers(lexer, true, false, "return", x.flags, x.type) != 0)
        goto done;

    goto check_type;

check_type:

    if (_check_type(x.flags, x.type) != 0 && !(x.flags & FLAG_UNCHECKED))
    {
        lexer.SetErr("undefined return type: %s\n", x.type.c_str());
        goto done;
    }

    rc = 0;

done:

    return rc;
}

static int _parse_field(Lexer& lexer, const Struct& s, Field& x, bool& found)
{
    int rc = -1;
    Tok tok = TOK_ERR;
    bool signed_type = false;
    bool unsigned_type = false;

    x.Clear();

    /* '[' ... ']' [const] [struct] [signed] type [*] name */

    switch (tok = lexer.Next())
    {
        case TOK_CLOSE_BRACE:
            goto parse_close_brace;
        case TOK_OPEN_BRACKET:
            goto parse_qualifiers;
        case TOK_CONST:
            goto parse_const;
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_qualifiers:

    if (_parse_qualifiers(lexer, x.flags, x.qvals) != 0)
        goto done;

    switch (tok = lexer.Next())
    {
        case TOK_CONST:
            goto parse_const;
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_const:

    x.flags |= FLAG_CONST;

    switch (tok = lexer.Next())
    {
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_struct:

    x.flags |= FLAG_STRUCT;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_signed:

    signed_type = true;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_unsigned:

    unsigned_type = true;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_type:

    if (signed_type)
        x.type = "signed " + string(lexer.text);
    else if (unsigned_type)
        x.type = "unsigned " + string(lexer.text);
    else
        x.type = string(lexer.text);

    switch (tok = lexer.Next())
    {
        case TOK_PTR:
            goto parse_ptr;
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_ptr:

    x.flags |= FLAG_PTR;

    switch (tok = lexer.Next())
    {
#ifdef HAVE_PTR_PTR
        case TOK_PTR:
            goto parse_ptr_ptr;
#endif /* HAVE_PTR_PTR */
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

#ifdef HAVE_PTR_PTR
parse_ptr_ptr:

    x.flags &= ~FLAG_PTR;
    x.flags |= FLAG_PTR_PTR;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }
#endif /* HAVE_PTR_PTR */

parse_name:

    found = true;
    x.name = lexer.text;

    if (s.FindField(x.name) != (size_t)-1)
    {
        lexer.SetErr("duplicate member: %s", x.name.c_str());
        goto done;
    }

    switch (tok = lexer.Next())
    {
        case TOK_OPEN_BRACKET:
            goto parse_subscript;
        case TOK_SEMICOLON:
            goto parse_semicolon;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_subscript:

    // '[' [0-9][0-9]* ']'

    x.flags |= FLAG_ARRAY;

    if (x.flags & FLAG_PTR)
    {
        lexer.SetErr("arrays of pointers not supported");
        goto done;
    }

    if ((tok = lexer.Next()) == TOK_NUMBER)
    {
        char* end = NULL;
        unsigned long tmp = strtoul(lexer.text, &end, 10);

        if ((!end && *end) || tmp >= UINT_MAX)
        {
            lexer.SetErr("invalid subscript: %s", lexer.text);
            goto done;
        }

        x.subscript = (unsigned int)tmp;
        tok = lexer.Next();
    }

    if (tok != TOK_CLOSE_BRACKET)
    {
        lexer.SetErr("invalid subscript expression");
        goto done;
    }

    switch (tok = lexer.Next())
    {
        case TOK_SEMICOLON:
            goto parse_semicolon;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_semicolon:

    rc = 0;
    goto check_qualifiers;

parse_close_brace:

    rc = 1;
    goto check_qualifiers;

check_qualifiers:

    if (_check_qualifiers(lexer, false, false, x.name, x.flags, x.type) != 0)
    {
        rc = -1;
        goto done;
    }

    goto check_type;

check_type:

    if (x.name.size() && _check_type(x.flags, x.type) != 0 &&
        !(x.flags & FLAG_UNCHECKED))
    {
        rc = -1;
        lexer.SetErr("undefined field type: %s\n", x.type.c_str());
    }

    goto done;

done:

    return rc;
}

static int _parse_param(Lexer& lexer, const Function& f, Param& x, bool& found)
{
    int rc = -1;
    Tok tok = TOK_ERR;
    bool signed_type = false;
    bool unsigned_type = false;

    x.Clear();

    /* '[' ... ']' [const] [struct] [signed] type [*] name */

    switch (tok = lexer.Next())
    {
        case TOK_CLOSE_PAREN:
            goto parse_close_paren;
        case TOK_OPEN_BRACKET:
            goto parse_qualifiers;
        case TOK_CONST:
            goto parse_const;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_qualifiers:

    if (_parse_qualifiers(lexer, x.flags, x.qvals) != 0)
        goto done;

    switch (tok = lexer.Next())
    {
        case TOK_CONST:
            goto parse_const;
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_const:

    x.flags |= FLAG_CONST;

    switch (tok = lexer.Next())
    {
        case TOK_SIGNED:
            goto parse_signed;
        case TOK_UNSIGNED:
            goto parse_unsigned;
        case TOK_STRUCT:
            goto parse_struct;
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_struct:

    x.flags |= FLAG_STRUCT;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_signed:

    signed_type = true;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_unsigned:

    unsigned_type = true;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_type;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_type:

    if (signed_type)
        x.type = "signed " + string(lexer.text);
    else if (unsigned_type)
        x.type = "unsigned " + string(lexer.text);
    else
        x.type = string(lexer.text);

    switch (tok = lexer.Next())
    {
        case TOK_PTR:
            goto parse_ptr;
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_ptr:

    x.flags |= FLAG_PTR;

    switch (tok = lexer.Next())
    {
#ifdef HAVE_PTR_PTR
        case TOK_PTR:
            goto parse_ptr_ptr;
#endif /* HAVE_PTR_PTR */
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

#ifdef HAVE_PTR_PTR
parse_ptr_ptr:

    x.flags &= ~FLAG_PTR;
    x.flags |= FLAG_PTR_PTR;

    switch (tok = lexer.Next())
    {
        case TOK_IDENTIFIER:
            goto parse_name;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }
#endif /* HAVE_PTR_PTR */

parse_name:

    found = true;
    x.name = lexer.text;

    if (f.FindParam(x.name) != (size_t)-1)
    {
        lexer.SetErr("redefinition of parameter: %s", x.name.c_str());
        goto done;
    }

    switch (tok = lexer.Next())
    {
        case TOK_OPEN_BRACKET:
            goto parse_subscript;
        case TOK_COMMA:
            goto parse_comma;
        case TOK_CLOSE_PAREN:
            goto parse_close_paren;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_subscript:

    // '[' [0-9][0-9]* ']'
    x.flags |= FLAG_ARRAY;

    if (x.flags & FLAG_PTR)
    {
        lexer.SetErr("arrays of pointers not supported");
        goto done;
    }

    if ((tok = lexer.Next()) == TOK_NUMBER)
    {
        char* end = NULL;
        unsigned long tmp = strtoul(lexer.text, &end, 10);

        if ((!end && *end) || tmp >= UINT_MAX)
        {
            lexer.SetErr("invalid subscript: %s", lexer.text);
            goto done;
        }

        x.subscript = (unsigned int)tmp;
        tok = lexer.Next();
    }

    if (tok != TOK_CLOSE_BRACKET)
    {
        lexer.SetErr("invalid subscript expression");
        goto done;
    }

    switch (tok = lexer.Next())
    {
        case TOK_COMMA:
            goto parse_comma;
        case TOK_CLOSE_PAREN:
            goto parse_close_paren;
        default:
            lexer.SetErr("syntax error");
            goto done;
    }

parse_comma:

    rc = 0;
    goto check_qualifiers;

parse_close_paren:

    rc = 1;
    goto check_qualifiers;

check_qualifiers:

    if (_check_qualifiers(lexer, false, true, x.name, x.flags, x.type) != 0)
    {
        rc = -1;
        goto done;
    }

    goto check_type;

check_type:

    if (x.type.size() && _check_type(x.flags, x.type) != 0 &&
        !(x.flags & FLAG_UNCHECKED))
    {
        lexer.SetErr("undefined parameter type: %s\n", x.type.c_str());
        rc = -1;
        goto done;
    }

done:

    return rc;
}

static int _check_function_qualifiers(Lexer& lexer, const vector<Param>& params)
{
    int rc = -1;

    /* Check [count=param] qualifier */
    for (size_t i = 0; i < params.size(); i++)
    {
        const Param& p = params[i];

        if (p.flags & FLAG_COUNT)
        {
            if (!_is_number(p.qvals.count))
            {
                size_t pos = FindParam(params, p.qvals.count);

                // If qualifier parameter argument not found:
                if (pos == (size_t)-1)
                {
                    lexer.SetErr(
                        "parameter given by [count=%s] not found",
                        p.qvals.count.c_str());
                    goto done;
                }

                // If qualifier parameter argument is not a counter:
                if (!params[pos].IsCounter())
                {
                    lexer.SetErr(
                        "parameter given by [count=%s] is not a counter",
                        p.qvals.count.c_str());
                    goto done;
                }
            }
        }
    }

    rc = 0;

    goto done;
done:
    return rc;
}

static int _check_struct_qualifiers(Lexer& lexer, Struct& s)
{
    int rc = -1;

    /* Check [count=param] qualifier */
    for (size_t i = 0; i < s.fields.size(); i++)
    {
        const Field& f = s.fields[i];

        if (f.flags & FLAG_COUNT)
        {
            if (!_is_number(f.qvals.count))
            {
                size_t pos = s.FindField(f.qvals.count);

                // If qualifier parameter argument not found:
                if (pos == (size_t)-1)
                {
                    lexer.SetErr(
                        "parameter given by [count=%s] not found",
                        f.qvals.count.c_str());
                    goto done;
                }

                // If qualifier parameter argument is not a counter:
                if (!s.fields[pos].IsCounter())
                {
                    lexer.SetErr(
                        "parameter given by [count=%s] is not a counter",
                        f.qvals.count.c_str());
                    goto done;
                }
            }
        }
    }

    rc = 0;

    goto done;
done:
    return rc;
}

static int _parse_function(Lexer& lexer, Function& x)
{
    int rc = -1;
    ReturnType return_type;
    Param param;
    Tok tok = TOK_ERR;

    /* Get return type */
    if (_parse_return_type(lexer, x.return_type) != 0)
        goto done;

    /* Get function name */
    {
        if ((tok = lexer.tok) != TOK_IDENTIFIER)
        {
            lexer.SetErr("expected function name: %s", lexer.text);
            goto done;
        }

        x.name = lexer.text;
    }

    /* Get open parenthesis */
    if ((tok = lexer.Next()) != TOK_OPEN_PAREN)
    {
        lexer.SetErr("expected open parenthesis: %s", lexer.text);
        goto done;
    }

    /* Parse parameters (handle empty parameter list first) */
    {
        bool found = false;

        while ((rc = _parse_param(lexer, x, param, found)) == 0)
        {
            x.params.push_back(param);
        }

        /* If not terminated with closing parenthesis */
        if (rc != 1)
            goto done;

        if (found)
            x.params.push_back(param);
    }

    /* Parse the semicolon */
    if ((tok = lexer.Next()) != TOK_SEMICOLON)
    {
        lexer.SetErr("expected semicolon: %s", lexer.text);
        goto done;
    }

    /* Check cross-parameter qualifiers */
    if (_check_function_qualifiers(lexer, x.params) != 0)
        goto done;

    rc = 0;

done:

    return rc;
}

static int _parse_struct(Lexer& lexer, Struct& x)
{
    int rc = -1;
    ReturnType return_type;
    Field field;
    Tok tok = TOK_ERR;

    /* Get struct name */
    {
        if ((tok = lexer.Next()) != TOK_IDENTIFIER)
        {
            lexer.SetErr("expected struct name: %s", lexer.text);
            goto done;
        }

        x.name = lexer.text;
    }

    /* Add this type to the types list */
    if (_add_type(FLAG_STRUCT, x.name) != 0)
    {
        lexer.SetErr("struct type already defined: %s", x.name.c_str());
        goto done;
    }

    /* Get open brace */
    if ((tok = lexer.Next()) != TOK_OPEN_BRACE)
    {
        lexer.SetErr("expected open brace: %s", lexer.text);
        goto done;
    }

    /* Parse fields */
    {
        bool found = false;

        while ((rc = _parse_field(lexer, x, field, found)) == 0)
        {
            x.fields.push_back(field);
        }

        /* If not terminated with closing brace */
        if (rc != 1)
            goto done;
    }

    /* Parse the semicolon */
    if ((tok = lexer.Next()) != TOK_SEMICOLON)
    {
        lexer.SetErr("expected semicolon: %s", lexer.text);
        goto done;
    }

    /* Check cross-parameter qualifiers */
    if (_check_struct_qualifiers(lexer, x) != 0)
        goto done;

    rc = 0;

done:

    return rc;
}

static int _parse_verbatim(Lexer& lexer, Verbatim& x)
{
    int rc = -1;
    Tok tok = TOK_ERR;

    /* Parse filename (string literal) */
    {
        if ((tok = lexer.Next()) != TOK_STRING)
        {
            lexer.SetErr("expected string literal: %s", lexer.text);
            goto done;
        }

        string text = lexer.text;
        x.filename = text.substr(1, text.size() - 2);
    }

    rc = 0;

done:

    return rc;
}

static int _parse_include(Lexer& lexer, string& filename)
{
    int rc = -1;
    Tok tok = TOK_ERR;

    filename.clear();

    /* Parse filename (string literal) */
    {
        if ((tok = lexer.Next()) != TOK_STRING)
        {
            lexer.SetErr("expected string literal: %s", lexer.text);
            goto done;
        }

        string text = lexer.text;
        filename = text.substr(1, text.size() - 2);
    }

    rc = 0;

done:

    return rc;
}

Parser::Parser()
{
}

Parser::~Parser()
{
    Clear();
}

void Parser::Clear()
{
    for (size_t i = 0; i < _objects.size(); i++)
        delete _objects[i];

    _objects.clear();
}

void Parser::Dump() const
{
    for (size_t i = 0; i < _objects.size(); i++)
    {
        _objects[i]->Dump();
    }
}

int Parser::Parse(Lexer& lexer)
{
    int rc = -1;
    Tok tok = TOK_ERR;

    Clear();

    /* Iterate until TOK_ERR=-1 or TOK_EOF=0 */
    while ((tok = lexer.Next()) > 0)
    {
        if (tok == TOK_VERBATIM)
        {
            Verbatim verbatim;

            if (_parse_verbatim(lexer, verbatim) != 0)
            {
                rc = -1;
                break;
            }

            _objects.push_back(new Verbatim(verbatim));
        }
        else if (tok == TOK_INCLUDE)
        {
            string filename;

            // Get the filename:
            if (_parse_include(lexer, filename) != 0)
            {
                rc = -1;
                break;
            }

            // Load this file into memory:
            vector<char> data;
            if (LoadFile(filename.c_str(), 1, data) != 0)
            {
                lexer.SetErr("failed to open: %s", filename.c_str());
                break;
            }

            // Create lexer instance:
            Lexer ilexer(filename.c_str(), &data[0]);

            // Parse this included file:
            Parser iparser;
            if (iparser.Parse(ilexer) != 0)
            {
                tok = TOK_ERR;
                lexer.Swap(ilexer);
                break;
            }

            // Transfer objects to up-level parser:
            for (size_t i = 0; i < iparser._objects.size(); i++)
            {
                _objects.push_back(iparser._objects[i]);
                iparser._objects.clear();
            }
        }
        else if (tok == TOK_STRUCT)
        {
            Struct s;

            if (_parse_struct(lexer, s) != 0)
            {
                rc = -1;
                break;
            }

            _objects.push_back(new Struct(s));
        }
        else if (tok == TOK_FUNCTION)
        {
            Function function;

            if (_parse_function(lexer, function) != 0)
            {
                rc = -1;
                break;
            }

            _objects.push_back(new Function(function));
        }
        else
        {
            lexer.SetErr("syntax error: %s", lexer.text);
            goto done;
        }
    }

    if (tok != TOK_EOF)
    {
        if (!lexer.TestErr())
            lexer.SetErr("syntax error");
        goto done;
    }

    rc = 0;

done:

    if (rc != 0)
        lexer.PutErr();

    return rc;
}

const std::vector<Object*>& Parser::Objects() const
{
    return _objects;
}
