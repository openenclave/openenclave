// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "generator.h"
#include <openenclave/host.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <sstream>
#include "types.h"

#define NEWCODE

using namespace std;

struct Ind
{
    Ind() : n(0)
    {
    }

    void operator++(int)
    {
        n++;
    }
    void operator--(int)
    {
        n--;
    }

    size_t n;
};

inline ostream& operator<<(ostream& os, const Ind& x)
{
    for (size_t i = 0; i < x.n; i++)
        os << "    ";
    return os;
}

OE_PRINTF_FORMAT(1, 2)
std::string pf(const char* fmt, ...)
{
    char buf[4096];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    return buf;
}

static string _Sub(const string& str, const string& from, const string& to)
{
    size_t pos = 0;
    string r = str;

    while ((pos = r.find(from, pos)) != string::npos)
    {
        r = r.substr(0, pos) + to + r.substr(pos + from.size());
        pos += to.size();
    }

    return r;
}

static string _NumToStr(size_t n)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%zu", n);
    return string(buf);
}

static string TypeName(unsigned int flags, const string& type)
{
    for (size_t i = 0; i < ntypes; i++)
    {
        if (types[i].idlName == type)
            return types[i].genName;
    }

    if (flags & FLAG_STRUCT)
        return "struct " + type;

    return type;
}

static string TypeTypeName(const string& type)
{
    for (size_t i = 0; i < ntypes; i++)
    {
        if (types[i].idlName == type)
            return types[i].genType;
    }

    return "OE_STRUCT_T";
}

static string sub(
    const string& str,
    const string& s0 = string(),
    const string& s1 = string(),
    const string& s2 = string(),
    const string& s3 = string(),
    const string& s4 = string(),
    const string& s5 = string(),
    const string& s6 = string(),
    const string& s7 = string(),
    const string& s8 = string(),
    const string& s9 = string())
{
    string r = str;
    r = _Sub(r, "$0", s0);
    r = _Sub(r, "$1", s1);
    r = _Sub(r, "$2", s2);
    r = _Sub(r, "$3", s3);
    r = _Sub(r, "$4", s4);
    r = _Sub(r, "$5", s5);
    r = _Sub(r, "$6", s6);
    r = _Sub(r, "$7", s7);
    r = _Sub(r, "$8", s8);
    r = _Sub(r, "$9", s9);
    return r;
}

static string _Basename(const string& path)
{
    size_t pos = path.rfind("/");

    if (pos == string::npos)
        return path;
    else
        return path.substr(pos + 1);
}

// Translate non-identifier characters to '_' */
static string _FixupFilename(const string& path)
{
    string tmp = path;

    for (size_t i = 0; i < tmp.size(); i++)
    {
        char c = tmp[i];

        if (!isalnum(c) && c != '_')
            c = '_';

        if (islower(c))
            c = toupper(c);

        tmp[i] = c;
    }

    return tmp;
}

static void _GenCommentBlock(ostream& os, const string& str)
{
    os << "/*" << endl;

    for (size_t i = 0; i < 80; i++)
        os << '*';
    os << endl;

    os << "**" << endl;
    os << "** " << str << endl;
    os << "**" << endl;

    for (size_t i = 0; i < 80; i++)
        os << '*';

    os << endl;
    os << "*/" << endl << endl;
}

static void _GenVerbatim(std::ostream& os, const Verbatim* verbatim)
{
    os << "#include \"" << verbatim->filename << "\"" << endl;
    os << endl;
}

static void _GenReturnType(std::ostream& os, const ReturnType& x)
{
    if (x.flags & FLAG_CONST)
        os << "const ";

    os << TypeName(x.flags, x.type) << " ";

    if (x.flags & FLAG_PTR)
        os << "*";
}

static void _GenParam(std::ostream& os, const Param& x)
{
    if (x.flags & FLAG_CONST)
        os << "const ";

    os << TypeName(x.flags, x.type) << " ";

    if (x.flags & FLAG_PTR)
        os << "*";

    if (x.flags & FLAG_REF)
        os << "*";

    os << x.name;

    if (x.flags & FLAG_ARRAY)
    {
        os << '[';

        if (x.subscript > 0)
            os << x.subscript;

        os << ']';
    }
}

static void _GenField(std::ostream& os, const Field& x)
{
    if (x.flags & FLAG_CONST)
        os << "const ";

    os << TypeName(x.flags, x.type) << " ";

    if (x.flags & FLAG_PTR)
        os << "*";

    os << x.name;

    if (x.flags & FLAG_ARRAY)
    {
        os << '[';

        if (x.subscript > 0)
            os << x.subscript;

        os << ']';
    }
}

static bool _IsZeroArray(const Param& p)
{
    return (p.flags & FLAG_ARRAY) && p.subscript == 0;
}

static void _GenStructDefinition(std::ostream& os, const Struct* s)
{
    // os << "typedef struct " << s->name << " __" << s->name << ";\n";
    // os << endl;
    os << "struct " << s->name << endl;
    os << "{\n";

    for (size_t i = 0; i < s->fields.size(); i++)
    {
        const Field& f = s->fields[i];

        os << "    ";
        _GenField(os, f);
        os << ";" << endl;
    }

    os << "};\n";
    os << endl;

    os << sub("extern const OE_StructTI $0_ti;\n", s->name) << endl;
}

static void _GenFunctionPrototype(std::ostream& os, const Function* f)
{
    os << "OE_EXTERNC ";

    _GenReturnType(os, f->returnType);

    os << f->name << "(";

    if (f->params.size())
        os << endl;

    for (size_t i = 0; i < f->params.size(); i++)
    {
        os << "    ";
        _GenParam(os, f->params[i]);

        if (i + 1 != f->params.size())
            os << ",\n";
    }

    os << ");\n";
    os << endl;
}

static void _GenFunctionStruct(std::ostream& os, const Function* function)
{
    size_t count = 0;

    os << "struct " << function->name << "Args" << endl;
    os << "{" << endl;

    // Generate return field:
    {
        const ReturnType& rt = function->returnType;

        if (!rt.Empty())
        {
            os << "    ";

            if (rt.flags & FLAG_CONST)
                os << "const ";

            os << TypeName(rt.flags, rt.type) << " ";

            if (rt.flags & FLAG_PTR)
                os << "*";

            os << rt.name << ";" << endl;
            count++;
        }

        /* Generate padding field */
        os << sub("    unsigned char __pad$0[4];\n", _NumToStr(count));
    }

    // Generate parameter fields:
    for (size_t i = 0; i < function->params.size(); i++)
    {
        const Param& x = function->params[i];

        os << "    ";

        if (x.flags & FLAG_CONST)
            os << "const ";

        os << TypeName(x.flags, x.type) << " ";

        if (x.flags & FLAG_PTR)
            os << "*";

        os << x.name;

        if (x.flags & FLAG_ARRAY)
        {
            os << '[';

            if (x.subscript > 0)
                os << x.subscript;

            os << ']';
        }

        os << ";" << endl;
        count++;

        /* Generate padding field (for detecting buffer overruns) */
        if (i + 1 != function->params.size() || !_IsZeroArray(x))
            os << sub("    unsigned char __pad$0[4];\n", _NumToStr(count));
    }

    /* If no return type and no parameters, then generate dummy field */
    if (count == 0)
    {
        os << "    int __dummy;" << endl;
    }

    os << "};\n";
}

static void _GenSetArg(
    std::ostream& os,
    size_t index,         /* Index into the fields array */
    unsigned int flags,   /* flags from the parameter or return object */
    const string& prefix, /* what comes before the name (e.g., "s.") */
    const string& name,   /* name of the argument */
    const string& alloc)  /* name of allocator function (e.g., malloc) */
{
    const char text[] = "    __r = OE_SetArg(__ti, __a, $0, $1, $2$3, $4);\n"
                        "    if (__r != OE_OK)\n"
                        "        goto done;\n\n";

    string ref;
    if (flags & FLAG_REF)
        ref = "true";
    else
        ref = "0";

    os << sub(text, _NumToStr(index), ref, prefix, name, alloc);
}

static void _GenClearArg(
    std::ostream& os,
    size_t index,         /* Index into the fields array */
    unsigned int flags,   /* flags from the parameter or return object */
    const string& prefix, /* what comes before the name (e.g., "s.") */
    const string& name,
    const string& freeStr)
{
    const char text[] = "    __r = OE_ClearArg(__ti, __a, $0, $1, $2$3, $4);\n"
                        "    if (__r != OE_OK)\n"
                        "        goto done;\n\n";

    string ref;
    if (flags & FLAG_REF)
        ref = "true";
    else
        ref = "0";

    os << sub(text, _NumToStr(index), ref, prefix, name, freeStr);
}

static void _GenTrustedICALL(std::ostream& os, const Function* function)
{
    const Function& f = *function;
    const ReturnType& r = f.returnType;
    bool empty = (r.Empty() && f.params.size() == 0);
    string mallocStr = "OE_HostMalloc";
    string freeStr = "OE_HostFree";
    Ind ind;

    // ATTN: change signature of these functions to return OE_Result!

    os << pf("/* ICALL: %s(%u) */\n", __FILE__, __LINE__);
    os << sub("OE_ECALL void __$0(void* args)\n", f.name);
    os << "{" << endl;
    ind++;

    {
        const char text[] = "    OE_Result __r = OE_OK;\n"
                            "\n";
        os << sub(text, f.name);
    }

    if (!empty)
    {
        const char text[] = "    const OE_StructTI* __ti = &$0Args_ti;\n"
                            "    typedef struct $0Args __Args;\n"
                            "    __Args* __args = (__Args*)args;\n"
                            "    __Args __buf;\n"
                            "    __Args* __a = &__buf;\n"
                            "\n"
                            "    OE_Memset(__a, 0, sizeof(__Args));\n"
                            "\n";
        os << sub(text, f.name);
    }

    // Check pre-constraints first:
    if (!empty)
    {
        const char text[] = "    __r = OE_CheckPreConstraints(__ti, args);\n"
                            "    if (__r != OE_OK)\n"
                            "        goto done;\n"
                            "\n";
        os << text;
    }

    // Copy input parameters into enclave memory (if any):
    for (size_t i = 0; i < f.params.size(); i++)
    {
        const Param& p = f.params[i];

        string amp;
        string ref = "false";

        if ((p.flags & FLAG_REF) || (p.flags & FLAG_PTR))
        {
            amp = "&";
            ref = "true";
        }
        else if (!(p.flags & FLAG_PTR) && !(p.flags & FLAG_ARRAY))
            amp = "&";

        if (p.flags & FLAG_IN)
        {
            const char text[] =
                "    __r = OE_SetArg("
                "__ti, __args, $0, $1, (void*)$2__a->$3, malloc);\n"
                "    if (__r != OE_OK)\n"
                "        goto done;\n\n";

            size_t index = r.Empty() ? i : i + 1;
            os << sub(text, _NumToStr(index), ref, amp, p.name);
        }
        else if (p.flags & FLAG_PTR && !(p.flags & FLAG_REF))
        {
            /* Clear output parameter before call dispatch */
            const char text[] =
                "    __r = OE_InitArg("
                "__ti, __args, $0, $1, (void*)$2__a->$3, malloc);\n"
                "    if (__r != OE_OK)\n"
                "        goto done;\n\n";

            size_t index = r.Empty() ? i : i + 1;
            os << sub(text, _NumToStr(index), ref, amp, p.name);
        }
    }

    /* Fill structure padding with the 0xDD byte */
    if (!empty)
    {
        const char text[] = "    __r = OE_PadStruct(__ti, __a);\n"
                            "    if (__r != OE_OK)\n"
                            "        goto done;\n\n";
        os << text;
    }

    /* Write function call expression */
    {
        os << ind;

        if (!r.Empty())
            os << "__a->" << r.name << " = ";

        if (f.params.size() == 0)
        {
            os << f.name << "();\n";
        }
        else
        {
            os << f.name << "(\n";

            ind++;
            for (size_t i = 0; i < f.params.size(); i++)
            {
                const Param& p = f.params[i];

                os << ind;

                if (p.flags & FLAG_REF)
                {
                    /* Note that the void** argument was passed in a void*
                     * structure field. So upon return, the meaning of the
                     * argument has change from a reference (void**) to a
                     * void* pointer to the object.
                     */
                    const char text[] = "__args->$0 ? &__a->$0 : NULL";
                    os << sub(text, p.name);
                }
                else
                    os << "__a->" << p.name;

                if (i + 1 != f.params.size())
                    os << ",\n";
            }
            ind--;

            os << ");\n";
        }
        os << endl;
    }

    // Check for heap buffer overruns:
    if (!empty)
    {
        const char text[] = "    __r = OE_CheckStruct(__ti, __a);\n"
                            "    if (__r != OE_OK)\n"
                            "        goto done;\n"
                            "\n";
        os << text;
    }

    // Export the structure to outside memory:
    if (!empty)
    {
        os << endl;

        // Copy return value back to caller's memory:
        if (!r.Empty())
        {
            unsigned int f = r.flags;

            if (f & FLAG_PTR)
                f |= FLAG_REF;

            _GenSetArg(os, 0, f, "&__args->", r.name, mallocStr);
        }

        // Copy parameters back to caller's memory:
        for (size_t i = 0; i < f.params.size(); i++)
        {
            const Param& p = f.params[i];

            if (p.flags & FLAG_OUT)
            {
                string prefix;

                if (p.flags & FLAG_REF)
                    prefix = "&__args->";
                else
                    prefix = "__args->";

                size_t index = r.Empty() ? i : i + 1;

                /* If in-out argument */
                if (p.flags & FLAG_IN)
                    _GenClearArg(os, index, p.flags, prefix, p.name, freeStr);

                _GenSetArg(os, index, p.flags, prefix, p.name, mallocStr);
            }
        }

        // Check pre-constraints first:
        {
            const char text[] =
                "    __r = OE_CheckPostConstraints(__ti, args);\n"
                "    if (__r != OE_OK)\n"
                "        goto done;\n"
                "\n";
            os << text;
        }

        /* ATTN: figure out how to preserve the return value */
        const char text[] = "done:\n"
                            "    OE_DestroyStruct(__ti, __a, free);\n"
                            "\n"
                            "    (void)__r;\n";
        os << text;
    }
    else
    {
        const char text[] = "\n"
                            "    (void)__r;\n";
        os << text;
    }

    ind--;
    os << "}" << endl << endl;
}

static void _GenUntrustedICALL(std::ostream& os, const Function* function)
{
    const Function& f = *function;
    const ReturnType& r = f.returnType;
    bool empty = (r.Empty() && f.params.size() == 0);
    Ind ind;

    // ATTN: change signature of these functions to return OE_Result!

    os << pf("/* ICALL: %s(%u) */\n", __FILE__, __LINE__);
    os << sub("OE_OCALL void __$0(void* args)\n", f.name);
    os << "{" << endl;
    ind++;

    const char UNTRUSTED[] = "    struct $0Args* __a = (struct $0Args*)args;\n";

    if (!empty)
    {
        os << sub(UNTRUSTED, f.name);
        os << endl;
    }

    os << ind;

    if (!r.Empty())
        os << "__a->" << r.name << " = ";

    if (f.params.size() == 0)
    {
        os << f.name << "();\n";
    }
    else
    {
        os << f.name << "(\n";

        ind++;
        for (size_t i = 0; i < f.params.size(); i++)
        {
            const Param& p = f.params[i];

            os << ind;

            if (p.flags & FLAG_REF)
                os << "&__a->" << p.name;
            else
                os << "__a->" << p.name;

            if (i + 1 != f.params.size())
                os << ",\n";
        }
        ind--;

        os << ");\n";
    }

    ind--;
    os << "}" << endl << endl;
}

static void _GenCallOutFunctionPrototype(
    std::ostream& os,
    bool trusted,
    const Function* f,
    bool terminate)
{
    os << "OE_EXTERNC ";

    const ReturnType& rt = f->returnType;

    os << "OE_Result " << f->name << "(";

    if (!rt.Empty() || f->params.size() != 0)
        os << "\n";

    if (!trusted)
    {
        os << "    ";
        os << "OE_Enclave* enclave";
    }

    if (!rt.Empty() || f->params.size())
    {
        if (!trusted)
            os << ",\n";

        if (!rt.Empty())
        {
            os << "    ";
            _GenReturnType(os, rt);

            os << "*" << rt.name;

            if (f->params.size())
                os << ",\n";
        }

        for (size_t i = 0; i < f->params.size(); i++)
        {
            os << "    ";
            _GenParam(os, f->params[i]);

            if (i + 1 != f->params.size())
                os << ",\n";
        }
    }

    if (terminate)
        os << ");" << endl << endl;
    else
        os << ")" << endl;
}

static void _GenOCALL(std::ostream& os, const Function* f)
{
    const ReturnType& r = f->returnType;
    const string& fn = f->name;
    string hostAllocStr = "OE_HostAllocForCallHost";
    string mallocStr = "_HostAllocForCallHost";
    string freeStr = "_HostFreeForCallHost";

    os << pf("/* OCALL: %s(%u) */\n", __FILE__, __LINE__);
    _GenCallOutFunctionPrototype(os, true, f, false);

    // Generate function body:
    Ind ind;
    ind++;

    os << "{" << endl;
    os << "    OE_Result __r = OE_UNEXPECTED;\n";
    os << ind << sub("const OE_StructTI* __ti = &$0Args_ti;\n", fn);
    os << ind << sub("typedef struct $0Args __Args;\n", fn);
    os << ind << "__Args __args;\n";
    os << ind << "__Args* __a = NULL;\n" << endl;

    os << "    /**************************/\n";
    os << "    /*** create args struct ***/\n";
    os << "    /**************************/\n";
    os << endl;

    os << "    OE_Memset(&__args, 0, sizeof(__Args));\n";

    for (size_t i = 0; i < f->params.size(); i++)
    {
        const Param& p = f->params[i];

        if (p.subscript)
        {
            os << ind;
            os << sub(
                "_ConstMemcpy(__args.$0, $0, sizeof(__args.$0));\n", p.name);
        }
        else
        {
            if (p.flags & FLAG_REF)
            {
                os << ind << sub("if ($0)\n", p.name);
                os << ind << sub("    __args.$0 = *$0;\n", p.name);
            }
            else
                os << ind << sub("__args.$0 = $0;\n", p.name);
        }
    }
    os << "\n";

    {
        const char text[] = "    if (!(__a = (__Args*)$0(sizeof(__Args))))\n"
                            "    {\n"
                            "        __r = OE_OUT_OF_MEMORY;\n"
                            "        goto done;\n"
                            "    }\n"
                            "    OE_Memset(__a, 0, sizeof(__Args));\n"
                            "\n";

        os << sub(text, hostAllocStr);
    }

    // Copy parameters into args structure */
    for (size_t i = 0; i < f->params.size(); i++)
    {
        const Param& p = f->params[i];

        string amp;
        string ref = "false";

        if ((p.flags & FLAG_REF) || (p.flags & FLAG_PTR))
        {
            amp = "&";
            ref = "true";
        }
        else if (!(p.flags & FLAG_PTR) && !(p.flags & FLAG_ARRAY))
            amp = "&";

        if (p.flags & FLAG_IN)
        {
            const char text[] =
                "    __r = OE_SetArg("
                "__ti, &__args, $0, $1, (void*)$2__a->$3, $4);\n"
                "    if (__r != OE_OK)\n"
                "        goto done;\n\n";

            size_t index = r.Empty() ? i : i + 1;
            os << sub(text, _NumToStr(index), ref, amp, p.name, mallocStr);
        }
        else if (p.flags & FLAG_PTR)
        {
            /* Clear output parameter before call dispatch */
            const char text[] =
                "    __r = OE_InitArg("
                "__ti, &__args, $0, $1, (void*)$2__a->$3, $4);\n"
                "    if (__r != OE_OK)\n"
                "        goto done;\n\n";

            size_t index = r.Empty() ? i : i + 1;
            os << sub(text, _NumToStr(index), ref, amp, p.name, mallocStr);
        }
    }

    os << "    /********************/\n";
    os << "    /*** perform call ***/\n";
    os << "    /********************/\n";
    os << endl;

    {
        os << ind;
        os << "__r = OE_CallHost(\"__" << fn << "\", __a);\n";
    }

    os << ind << "if (__r != OE_OK)\n";
    os << ind << "    goto done;\n";
    os << "\n";

    os << "    /********************/\n";
    os << "    /*** return value ***/\n";
    os << "    /********************/\n";
    os << endl;

    size_t index = 0;

    if (!r.Empty())
    {
        unsigned int f = r.flags;

        if (f & FLAG_PTR)
            f |= FLAG_REF;

        _GenSetArg(os, index, f, "", r.name, "malloc");
        index++;
    }

    os << "    /*************************/\n";
    os << "    /*** output parameters ***/\n";
    os << "    /*************************/\n";
    os << endl;

    for (size_t i = 0; i < f->params.size(); i++, index++)
    {
        const Param& p = f->params[i];

        if (!(p.flags & FLAG_OUT))
            continue;

        if (p.flags & FLAG_OUT)
        {
            string prefix;

            if (p.flags & FLAG_REF)
                prefix = "&";

            /* If in-out argument */
            if (p.flags & FLAG_IN)
                _GenClearArg(os, index, p.flags, prefix, p.name, freeStr);

            _GenSetArg(os, index, p.flags, prefix, p.name, mallocStr);
        }
    }

    // Done block:
    {
        const char text[] = "done:\n"
                            "\n"
                            "    if (__a)\n"
                            "        OE_FreeStruct(__ti, __a, $0);\n"
                            "\n"
                            "    return __r;\n"
                            "}\n";
        os << sub(text, freeStr);
    }

    os << endl;
}

static void _GenECALL(std::ostream& os, const Function* f)
{
    const ReturnType& r = f->returnType;
    const string& fn = f->name;
    Ind ind;

    os << pf("/* ECALL: %s(%u) */\n", __FILE__, __LINE__);
    _GenCallOutFunctionPrototype(os, false, f, false);

    // Generate function body:
    ind++;
    os << "{" << endl;
    os << "    OE_Result __r = OE_UNEXPECTED;\n";
    os << ind << sub("struct $0Args __args;\n", fn);
    os << endl;

    os << "    /**************************/\n";
    os << "    /*** create args struct ***/\n";
    os << "    /**************************/\n";
    os << endl;

    os << "    memset(&__args, 0, sizeof(__args));\n";

    for (size_t i = 0; i < f->params.size(); i++)
    {
        const Param& p = f->params[i];

        if (p.subscript)
        {
            os << ind;
            os << sub(
                "_ConstMemcpy(__args.$0, $0, sizeof(__args.$0));\n", p.name);
        }
        else
        {
            if (p.flags & FLAG_REF)
            {
                /* Note: passing void** in void* field */
                const char text[] = "    __args.$0 = (void*)$0;\n\n";
                os << sub(text, p.name);
            }
            else
                os << ind << sub("__args.$0 = $0;\n", p.name);
        }
    }
    os << "\n";

    os << "    /********************/\n";
    os << "    /*** perform call ***/\n";
    os << "    /********************/\n";
    os << endl;

    os << ind;
    os << sub("__r = OE_CallEnclave(enclave, \"__$0\", &__args);\n", fn);

    os << ind << "if (__r != OE_OK)\n";
    os << ind << "    goto done;\n";
    os << "\n";

    os << "    /********************/\n";
    os << "    /*** return value ***/\n";
    os << "    /********************/\n";
    os << endl;

    size_t index = 0;

    if (!r.Empty())
    {
        os << ind << "if (ret)\n";
        os << ind << "    *ret = __args.ret;\n";
        os << endl;
    }

    os << "    /*************************/\n";
    os << "    /*** output parameters ***/\n";
    os << "    /*************************/\n";
    os << endl;

    for (size_t i = 0; i < f->params.size(); i++, index++)
    {
        const Param& p = f->params[i];

        if (!(p.flags & FLAG_OUT))
            continue;

        if (p.flags & FLAG_REF)
        {
            const char text[] = "    if ($0)\n"
                                "        *$0 = __args.$0;\n\n";
            os << sub(text, p.name);
        }
        else if (p.flags & FLAG_ARRAY)
        {
            os << ind;
            os << sub("memcpy($0, __args.$0, sizeof(__args.$0));\n\n", p.name);
        }
    }

    {
        const char text[] = "done:\n"
                            "    return __r;\n"
                            "}\n";
        os << text;
    }

    os << endl;
}

static unsigned int _CountBits(unsigned int x)
{
    unsigned int nbits = 0;

    for (unsigned int i = 0; i < 32; i++)
    {
        if (x & (1 << i))
            nbits++;
    }

    return nbits;
}

static void _GenFlag(
    ostream& os,
    unsigned int flags,
    unsigned int flag,
    const char* name,
    unsigned int& nbits)
{
    if (flags & flag)
    {
        os << name;
        if (--nbits)
            os << '|';
    }
}

static void _GenFlags(ostream& os, unsigned int flags)
{
    unsigned int mask = 0;
    mask |= FLAG_ECALL;
    mask |= FLAG_OCALL;
    mask |= FLAG_IN;
    mask |= FLAG_OUT;
    mask |= FLAG_REF;
    mask |= FLAG_CONST;
    mask |= FLAG_PTR;
    mask |= FLAG_ARRAY;
    mask |= FLAG_UNCHECKED;
    mask |= FLAG_COUNT;
    mask |= FLAG_STRING;
    mask |= FLAG_OPT;

    if (flags & mask)
    {
        unsigned int nbits = _CountBits(flags & mask);
        _GenFlag(os, flags, FLAG_ECALL, "OE_FLAG_ECALL", nbits);
        _GenFlag(os, flags, FLAG_OCALL, "OE_FLAG_OCALL", nbits);
        _GenFlag(os, flags, FLAG_IN, "OE_FLAG_IN", nbits);
        _GenFlag(os, flags, FLAG_OUT, "OE_FLAG_OUT", nbits);
        _GenFlag(os, flags, FLAG_REF, "OE_FLAG_REF", nbits);
        _GenFlag(os, flags, FLAG_CONST, "OE_FLAG_CONST", nbits);
        _GenFlag(os, flags, FLAG_PTR, "OE_FLAG_PTR", nbits);
        _GenFlag(os, flags, FLAG_ARRAY, "OE_FLAG_ARRAY", nbits);
        _GenFlag(os, flags, FLAG_UNCHECKED, "OE_FLAG_UNCHECKED", nbits);
        _GenFlag(os, flags, FLAG_COUNT, "OE_FLAG_COUNT", nbits);
        _GenFlag(os, flags, FLAG_STRING, "OE_FLAG_STRING", nbits);
        _GenFlag(os, flags, FLAG_OPT, "OE_FLAG_OPT", nbits);
        os << ", /* flags */\n";
    }
    else
    {
        os << "0, /* flags */\n";
    }
}

static int _GenFieldTypeInfo(std::ostream& os, const Struct& s, const Field& f)
{
    int rc = -1;
    Ind ind;
    ind++;

    string ttn = TypeTypeName(f.type);
    string tn = TypeName(f.flags, f.type);

    os << ind << "{\n";
    ind++;
    {
        // OE_FieldTI.flags:
        os << ind;
        _GenFlags(os, f.flags);

        // OE_FieldTI.name:
        os << ind << '"' << f.name << "\", /* name */\n";

        // OE_FieldTI.type:
        os << ind << ttn << ", /* type */\n";

        // OE_FieldTI.structTI:
        if (f.flags & FLAG_STRUCT && !(f.flags & FLAG_UNCHECKED))
            os << ind << sub("&$0_ti, /* structTI */\n", f.type);
        else
            os << ind << "NULL, /* structTI */\n";

        // OE_FieldTI.countField:
        if (f.flags & FLAG_COUNT)
            os << ind << '"' << f.qvals.count << "\", /* countField */\n";
        else
            os << ind << "NULL, /* countField */\n";

        // OE_FieldTI.offset:
        os << ind << "OE_OFFSETOF(struct " << s.name << ", " << f.name
           << "),\n";

        // OE_FieldTI.size:
        if (f.flags & FLAG_PTR)
            os << ind << "sizeof(void*), /* size */\n";
        else if (f.flags & FLAG_ARRAY)
        {
            os << ind << "sizeof(" << tn << ") * " << f.subscript
               << ", /* size */\n";
        }
        else
            os << ind << "sizeof(" << tn << "), /* size */\n";

        // OE_FieldTI.subscript:
        os << ind << f.subscript << ", /* subscript */" << endl;
    }
    ind--;
    os << ind << "},\n";

    rc = 0;
    return rc;
}

static int _GenStructTypeInfo(std::ostream& os, const Struct& s)
{
    int rc = -1;

    // Generate fields type-info:
    {
        // Generate forward declaration of struct type info:
        os << sub("extern const OE_StructTI $0_ti;\n\n", s.name);

        {
            os << sub(
                "static const OE_FieldTI _$0_fields_ti[] =\n"
                "{\n",
                s.name);

            for (size_t i = 0; i < s.fields.size(); i++)
            {
                const Field& f = s.fields[i];

                if (_GenFieldTypeInfo(os, s, f) != 0)
                    goto done;
            }

            os << sub("};\n\n");
        }

        {
            Ind ind;
            ind++;

            os << sub(
                "const OE_StructTI $0_ti =\n"
                "{\n",
                s.name);

            os << ind;
            os << "0, /* flags */\n";

            os << ind;
            os << '"' << s.name << "\", /* name */\n";

            os << ind;
            os << sub("sizeof(struct $0), /* size */\n", s.name);

            os << ind;
            os << sub("_$0_fields_ti, /* fields */\n", s.name);

            os << ind;
            os << sub("OE_COUNTOF(_$0_fields_ti) /* nfields */\n", s.name);

            os << sub("};\n\n");
        }
    }

    rc = 0;

done:
    return rc;
}

static int _GenReturnTypeTypeInfo(
    std::ostream& os,
    const Function& f,
    const ReturnType& r)
{
    int rc = -1;
    Ind ind;
    ind++;

    string ttn = TypeTypeName(r.type);
    string tn = TypeName(r.flags, r.type);

    os << ind << "{\n";
    ind++;
    {
        // OE_FieldTI.flags:
        os << ind;

        _GenFlags(os, r.flags);

        // OE_FieldTI.name:
        os << ind << '"' << r.name << "\", /* name */\n";

        // OE_FieldTI.type:
        os << ind << ttn << ", /* type */\n";

        // OE_FieldTI.structTI:
        if (r.flags & FLAG_STRUCT && !(r.flags & FLAG_UNCHECKED))
            os << ind << sub("&$0_ti, /* structTI */\n", r.type);
        else
            os << ind << "NULL, /* structTI */\n";

        // OE_FieldTI.countParam:
        if (r.flags & FLAG_COUNT)
            os << ind << '"' << r.qvals.count << "\", /* countParam */\n";
        else
            os << ind << "NULL, /* countParam */\n";

        // OE_FieldTI.offset:
        os << ind << "OE_OFFSETOF(struct " << f.name << "Args, " << r.name
           << "),\n";

        // OE_FieldTI.size:
        if (r.flags & FLAG_PTR)
            os << ind << "sizeof(void*), /* size */\n";
        else
            os << ind << "sizeof(" << tn << "), /* size */\n";

        // OE_FieldTI.subscript:
        os << ind << "0, /* subscript */" << endl;
    }
    ind--;
    os << ind << "},\n";

    rc = 0;
    return rc;
}

static int _GenParamTypeInfo(
    std::ostream& os,
    const Function& f,
    const Param& p)
{
    int rc = -1;
    Ind ind;
    ind++;

    string ttn = TypeTypeName(p.type);
    string tn = TypeName(p.flags, p.type);

    os << ind << "{\n";
    ind++;
    {
        // OE_FieldTI.flags:
        os << ind;
        _GenFlags(os, p.flags);

        // OE_FieldTI.name:
        os << ind << '"' << p.name << "\", /* name */\n";

        // OE_FieldTI.type:
        os << ind << ttn << ", /* type */\n";

        // OE_FieldTI.structTI:
        if (p.flags & FLAG_STRUCT && !(p.flags & FLAG_UNCHECKED))
            os << ind << sub("&$0_ti, /* structTI */\n", p.type);
        else
            os << ind << "NULL, /* structName */\n";

        // OE_FieldTI.countParam:
        if (p.flags & FLAG_COUNT)
            os << ind << '"' << p.qvals.count << "\", /* countParam */\n";
        else
            os << ind << "NULL, /* countParam */\n";

        // OE_FieldTI.offset:
        os << ind << "OE_OFFSETOF(struct " << f.name << "Args, " << p.name
           << "),\n";

        // OE_FieldTI.size:
        if (p.flags & FLAG_PTR)
            os << ind << "sizeof(void*), /* size */\n";
        else if (p.flags & FLAG_ARRAY)
        {
            os << ind << "sizeof(" << tn << ") * " << p.subscript
               << ", /* size */\n";
        }
        else
            os << ind << "sizeof(" << tn << "), /* size */\n";

        // OE_FieldTI.subscript:
        os << ind << p.subscript << ", /* subscript */" << endl;
    }
    ind--;
    os << ind << "},\n";

    rc = 0;
    return rc;
}

static int _GenFunctionTypeInfo(std::ostream& os, const Function& f)
{
    int rc = -1;

    // Generate params type-info:
    {
        // Generate forward declaration to function type-information:
        os << sub("extern const OE_StructTI $0Args_ti;\n\n", f.name);

        {
            os << sub(
                "static const OE_FieldTI _$0Args_fields_ti[] =\n"
                "{\n",
                f.name);

            if (!f.returnType.Empty())
            {
                if (_GenReturnTypeTypeInfo(os, f, f.returnType) != 0)
                    goto done;
            }

            for (size_t i = 0; i < f.params.size(); i++)
            {
                const Param& p = f.params[i];

                if (_GenParamTypeInfo(os, f, p) != 0)
                    goto done;
            }

            os << sub("};\n\n");
        }

        {
            Ind ind;
            ind++;

            os << sub(
                "const OE_StructTI $0Args_ti =\n"
                "{\n",
                f.name);

            os << ind << "0, /* flags */\n";

            os << ind << '"' << f.name << "\", /* name */\n";

            os << ind;
            os << sub("sizeof(struct $0Args), /* size */\n", f.name);

            os << ind;
            os << sub("_$0Args_fields_ti, /* params */\n", f.name);

            os << ind;
            os << sub("OE_COUNTOF(_$0Args_fields_ti) /* nparams */\n", f.name);

            os << sub("};\n\n");
        }
    }

    rc = 0;

done:
    return rc;
}

int Generator::GenerateSourceFile(
    std::ostream& os,
    const std::string& path,
    bool trusted,
    const std::vector<Object*>& objects)
{
    unsigned long flag1;
    unsigned long flag2;

    if (trusted)
    {
        flag1 = FLAG_ECALL;
        flag2 = FLAG_OCALL;
    }
    else
    {
        flag2 = FLAG_ECALL;
        flag1 = FLAG_OCALL;
    }

    if (trusted)
    {
        os << "#include <openenclave/enclave.h>" << endl;
        os << "#include <openenclave/bits/enclavelibc.h>" << endl;
    }
    else
        os << "#include <openenclave/host.h>" << endl;

    os << "#include <openenclave/bits/typeinfo.h>" << endl;
    os << "#include <stdlib.h>" << endl;

    // Include header for this source file:
    {
        string tmp = _Basename(path);

        size_t pos = tmp.rfind('.');

        if (pos != string::npos)
            tmp = tmp.substr(0, pos) + string(".h");

        os << "#include \"" << tmp << "\"" << endl;
    }

    // Generate verbatim definitions:
    for (size_t i = 0; i < objects.size(); i++)
    {
        const Verbatim* verbatim = dynamic_cast<const Verbatim*>(objects[i]);

        if (verbatim)
            _GenVerbatim(os, verbatim);
    }

    const char* MEMCPY = trusted ? "OE_Memcpy" : "memcpy";

    // Inject custom _ConstMemcpy() function:
    {
        const char text[] = "OE_INLINE void* _ConstMemcpy(\n"
                            "    const void* dest, \n"
                            "    const void* src,\n"
                            "    size_t n)\n"
                            "{\n"
                            "    return $0((void*)dest, src, n);\n"
                            "}\n\n";
        os << sub(text, MEMCPY) << endl;
    }

    // Inject wrapper functions for OCALL host stack allocations
    if (trusted)
    {
        const char mallocText[] =
            "OE_INLINE void* _HostAllocForCallHost(size_t size)\n"
            "{\n"
            "    return OE_HostAllocForCallHost(size);\n"
            "}\n\n";
        os << mallocText << endl;

        const char freeText[] =
            "OE_INLINE void _HostFreeForCallHost(void* ptr)\n"
            "{\n"
            "     OE_HostFreeForCallHost(ptr);\n"
            "}\n\n";
        os << freeText << endl;
    }

    // Generate struct type information:
    {
        _GenCommentBlock(os, "Type Information");

        for (size_t i = 0; i < objects.size(); i++)
        {
            const Struct* p = dynamic_cast<const Struct*>(objects[i]);

            if (p)
                _GenStructTypeInfo(os, *p);
        }

        for (size_t i = 0; i < objects.size(); i++)
        {
            const Function* p = dynamic_cast<const Function*>(objects[i]);

            if (p)
            {
                _GenFunctionStruct(os, p);
                os << endl;
                _GenFunctionTypeInfo(os, *p);
            }
        }
    }

    // Generate in-calls */
    _GenCommentBlock(os, "Inbound calls");
    for (size_t i = 0; i < objects.size(); i++)
    {
        const Function* f = dynamic_cast<const Function*>(objects[i]);

        if (f)
        {
            if (f->returnType.flags & flag1)
            {
                _GenFunctionPrototype(os, f);

                if (trusted)
                    _GenTrustedICALL(os, f);
                else
                    _GenUntrustedICALL(os, f);
            }
        }
    }

    // Generate out-calls */
    _GenCommentBlock(os, "Outbound calls");
    for (size_t i = 0; i < objects.size(); i++)
    {
        const Function* f = dynamic_cast<const Function*>(objects[i]);

        if (f)
        {
            if (f->returnType.flags & flag2)
            {
                if (trusted)
                    _GenOCALL(os, f);
                else
                    _GenECALL(os, f);
            }
        }
    }

    return 0;
}

int Generator::GenerateHeaderFile(
    std::ostream& os,
    const string& path,
    bool trusted,
    const std::vector<Object*>& objects)
{
    string fn = _FixupFilename(_Basename(path));
    unsigned int flag1;
    unsigned int flag2;

    if (trusted)
    {
        flag1 = FLAG_ECALL;
        flag2 = FLAG_OCALL;
    }
    else
    {
        flag2 = FLAG_ECALL;
        flag1 = FLAG_OCALL;
    }

    /* Prefix */
    {
        os << sub(
            "#ifndef _ENCIDL_$0\n"
            "#define _ENCIDL_$0\n"
            "\n",
            fn);
    }

    if (trusted)
        os << "#include <openenclave/enclave.h>" << endl;
    else
        os << "#include <openenclave/host.h>" << endl;

    os << endl;

    // Generate includes:
    for (size_t i = 0; i < objects.size(); i++)
    {
        const Verbatim* verbatim = dynamic_cast<const Verbatim*>(objects[i]);

        if (verbatim)
            _GenVerbatim(os, verbatim);
    }

    // Generate structure definitions:
    _GenCommentBlock(os, "Structure definitions");
    for (size_t i = 0; i < objects.size(); i++)
    {
        const Struct* s = dynamic_cast<const Struct*>(objects[i]);

        if (s)
            _GenStructDefinition(os, s);
    }

    // Generate function prototypes:
    _GenCommentBlock(os, "Inbound calls");
    for (size_t i = 0; i < objects.size(); i++)
    {
        const Function* f = dynamic_cast<const Function*>(objects[i]);

        if (f && (f->returnType.flags & flag1))
        {
            _GenFunctionPrototype(os, f);
        }
    }

    // Generate call-out function prototypes:
    _GenCommentBlock(os, "Outbound calls");
    for (size_t i = 0; i < objects.size(); i++)
    {
        const Function* f = dynamic_cast<const Function*>(objects[i]);

        if (f && (f->returnType.flags & flag2))
        {
            _GenCallOutFunctionPrototype(os, trusted, f, true);
        }
    }

    // Suffix:
    os << sub("#endif /* _ENCIDL_$0 */\n", fn);

    return 0;
}
