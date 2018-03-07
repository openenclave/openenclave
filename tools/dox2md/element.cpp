// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "element.h"
#include <expat.h>
#include <cassert>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace std;

//==============================================================================
//
// _TrimString()
//
//==============================================================================

static string _TrimString(const string& s)
{
    string r = s;

    while (isspace(r[0]))
        r.erase(0);

    size_t last = r.size();

    while (last > 0 && isspace(r[last - 1]))
    {
        last--;
        r.erase(last);
    }

    return r;
}

//==============================================================================
//
// _PrintString()
//
//==============================================================================

static void _PrintString(ostream& os, const char* s)
{
    os << '"';

    while (*s)
    {
        char c = *s++;

        if (isprint(c))
        {
            os << c;
        }
        else
        {
            switch (c)
            {
                case '\r':
                    os << "\\r";
                    break;
                case '\n':
                    os << "\\n";
                    break;
                case '\t':
                    os << "\\t";
                    break;
                case '\f':
                    os << "\\f";
                    break;
                case '\b':
                    os << "\\b";
                    break;
                case '\a':
                    os << "\\a";
                    break;
                default:
                {
                    char buf[4];
                    snprintf(buf, sizeof(buf), "\\%03o", c);
                    os << c;
                    break;
                }
            }
        }
    }

    os << '"';
}

//==============================================================================
//
// class Indent
//
//==============================================================================

class Indent
{
  public:
    Indent(size_t depth) : _depth(depth)
    {
    }

    void operator++(int)
    {
        _depth++;
    }

    void operator--(int)
    {
        _depth--;
    }

    size_t depth() const
    {
        return _depth;
    }

  private:
    size_t _depth;
};

ostream& operator<<(ostream& os, const Indent& indent)
{
    for (size_t i = 0; i < indent.depth(); i++)
    {
        os << "    ";
    }

    return os;
}

//==============================================================================
//
// class Attribute
//
//==============================================================================

Attribute::Attribute(const std::string& name, const std::string& value)
    : _name(name), _value(value)
{
}

const std::string& Attribute::name() const
{
    return _name;
}

const std::string& Attribute::value() const
{
    return _value;
}

void Attribute::dump(std::ostream& os, size_t depth) const
{
    Indent indent(depth);
    os << indent << _name << '=' << _value << endl;
}

//==============================================================================
//
// class Attributes
//
//==============================================================================

Attributes::Attributes()
{
}

Attributes::Attributes(const char** arr)
{
    while (*arr)
    {
        std::string name = *arr++;

        if (!*arr)
            break;

        std::string value = *arr++;

        _attrs.push_back(Attribute(name, value));
    }
}

void Attributes::append(const Attribute& attr)
{
    _attrs.push_back(attr);
}

size_t Attributes::size() const
{
    return _attrs.size();
}

const Attribute& Attributes::operator[](size_t i) const
{
    return _attrs[i];
}

bool const Attributes::contains(const std::string& name) const
{
    for (size_t i = 0; i < _attrs.size(); i++)
    {
        if (_attrs[i].name() == name)
            return true;
    }

    return false;
}

bool const Attributes::find(const std::string& name, std::string& value) const
{
    for (size_t i = 0; i < _attrs.size(); i++)
    {
        if (_attrs[i].name() == name)
        {
            value = _attrs[i].value();
            return true;
        }
    }

    return false;
}

std::string Attributes::operator[](const std::string& name) const
{
    std::string value;
    find(name, value);
    return value;
}

void Attributes::dump(std::ostream& os, size_t depth) const
{
    Indent indent(depth);

    for (size_t i = 0; i < _attrs.size(); i++)
        _attrs[i].dump(os, indent.depth());
}

//==============================================================================
//
// class Element
//
//==============================================================================

Element::Element()
{
}

const std::string& Element::name() const
{
    return _name;
}

void Element::name(const std::string& name)
{
    _name = name;
}

const Attributes& Element::attrs() const
{
    return _attrs;
}

void Element::attrs(const Attributes& attrs)
{
    _attrs = attrs;
}

const std::string& Element::chars() const
{
    return _chars;
}

std::string& Element::chars()
{
    return _chars;
}

void Element::chars(const std::string& chars)
{
    _chars = _TrimString(chars);
}

void Element::append(const Element& elem)
{
    _children.push_back(elem);
}

size_t Element::size() const
{
    return _children.size();
}

const Element& Element::operator[](size_t i) const
{
    return _children[i];
}

const Element& Element::operator[](const std::string& name) const
{
    static Element _not_found;

    for (size_t i = 0; i < _children.size(); i++)
    {
        const Element& e = _children[i];

        if (e.name() == name)
            return e;
    }

    return _not_found;
}

void Element::dump(std::ostream& os, size_t depth) const
{
    Indent indent(depth);

    os << indent << _name << endl;
    os << indent << "{" << endl;
    indent++;

    _attrs.dump(os, indent.depth());

    for (size_t i = 0; i < _children.size(); i++)
        _children[i].dump(os, indent.depth());

    if (_chars.size())
    {
        os << indent << "chars=";
        _PrintString(os, _chars.c_str());
        os << endl;
    }

    indent--;
    os << indent << "}" << endl;
}

bool Element::search(
    const std::string& xmlpath,
    const std::string& key,
    Element& elem) const
{
    size_t dot = xmlpath.find('.');

    if (dot == string::npos)
    {
        // Final component of path is an attribute name:

        string value;

        if (_attrs.find(xmlpath, value) && value == key)
        {
            elem = *this;
            return true;
        }
    }
    else
    {
        // Get the name of the left most element:
        string left = xmlpath.substr(0, dot);

        // Get excess path to the right:
        string right = xmlpath.substr(dot + 1);

        // Search each child:
        for (size_t i = 0; i < _children.size(); i++)
        {
            const Element& e = _children[i];

            if (e.name() == left)
            {
                if (e.search(right, key, elem))
                    return true;
            }
        }
    }

    // Not found!
    return false;
}

void Element::find(const std::string& name, std::vector<Element>& elements)
    const
{
    elements.clear();

    for (size_t i = 0; i < _children.size(); i++)
    {
        const Element& e = _children[i];

        if (e.name() == name)
            elements.push_back(e);
    }
}

bool Element::contains(const std::string& name) const
{
    for (size_t i = 0; i < _children.size(); i++)
    {
        if (_children[i].name() == name)
            return true;
    }

    return false;
}

typedef struct _Context
{
    Element root;
    std::stack<Element> stack;
} Context;

static void XMLCALL
_HandleStart(void* userData_, const XML_Char* name, const XML_Char** attrs)
{
    Context* context = (Context*)userData_;

    Element element;
    element.name(name);
    element.attrs(Attributes(attrs));

#if 0
    if (!context->stack.empty())
        context->stack.top().append(element);
#endif

    context->stack.push(element);
}

static void XMLCALL _HandleChars(void* userData_, const XML_Char* s, int len)
{
    Context* context = (Context*)userData_;
    Element& element = context->stack.top();
    element.chars() += string(s, len);
}

static void XMLCALL _HandleEnd(void* userData_, const XML_Char* name)
{
    Context* context = (Context*)userData_;

    if (context->stack.size() == 1)
    {
        context->root = context->stack.top();
        context->root.chars() = _TrimString(context->root.chars());
        context->stack.pop();
    }
    else
    {
        Element element = context->stack.top();
        element.chars() = _TrimString(element.chars());
        context->stack.pop();
        context->stack.top().append(element);
    }
}

bool Element::parse(const std::string& path, Element& root, Error& error)
{
    bool result = false;
    XML_Parser parser = NULL;
    Context context;
    FILE* is = NULL;
    int done;

    error.clear();

    /* Create parser instance */
    if (!(parser = XML_ParserCreate(NULL)))
    {
        error.set("XML_ParserCreate() failed");
        goto done;
    }

    /* Set handlers */
    XML_SetUserData(parser, &context);
    XML_SetElementHandler(parser, _HandleStart, _HandleEnd);
    XML_SetCharacterDataHandler(parser, _HandleChars);

    /* Open the input file */
    if (!(is = fopen(path.c_str(), "r")))
    {
        error.set("failed to open file: " + path);
        goto done;
    }

    /* Parse the document line by line */
    do
    {
        char buf[1024];
        size_t len;

        len = fread(buf, 1, sizeof(buf), is);
        done = len < sizeof(buf);

        if (XML_Parse(parser, buf, len, done) == XML_STATUS_ERROR)
        {
            error.set(
                XML_ErrorString(XML_GetErrorCode(parser)),
                XML_GetCurrentLineNumber(parser));
            goto done;
        }
    } while (!done);

    root = context.root;
    result = true;

done:

    if (parser)
        XML_ParserFree(parser);

    if (is)
        fclose(is);

    return result;
}
