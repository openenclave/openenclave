#ifndef _DOX2MD_ELEMENT_H
#define _DOX2MD_ELEMENT_H

#include <iostream>
#include <vector>
#include <string>
#include <stack>
#include <map>

class Error
{
public:

    Error()
    {
        clear();
    }

    void clear()
    {
        _line = 0;
        _message.clear();
    }

    void set(const std::string& message, unsigned int line = 0)
    {
        _line = line;
        _message = message;
    }

    std::string message() const { return _message; }

    unsigned int line() const { return _line; }

private:
    unsigned int _line;
    std::string _message;
};

class Attribute
{
public:

    Attribute(const std::string& name, const std::string& value);

    const std::string& name() const;

    const std::string& value() const;

    void dump(std::ostream& os = std::cout, size_t depth = 0) const;

private:
    std::string _name;
    std::string _value;
};

class Attributes
{
public:

    Attributes();

    Attributes(const char** arr);

    void append(const Attribute& attr);

    size_t size() const;

    const Attribute& operator[](size_t i) const;

    bool const contains(const std::string& name) const;

    bool const find(const std::string& name, std::string& value) const;

    std::string operator[](const std::string& name) const;

    void dump(std::ostream& os = std::cout, size_t depth = 0) const;

private:
    std::vector<Attribute> _attrs;
};

struct Element
{
public:

    Element();

    const std::string& name() const;

    void name(const std::string& name);

    const Attributes& attrs() const;

    void attrs(const Attributes& attrs);

    const std::string& chars() const;

    void chars(const std::string& chars);

    std::string& chars();

    void append(const Element& elem);

    size_t size() const;

    const Element& operator[](size_t i) const;

    const Element& operator[](const std::string& name) const;

    void dump(std::ostream& os = std::cout, size_t depth = 0) const;

    bool search(
        const std::string& xmlpath, 
        const std::string& key, 
        Element& elem) const;

    void find(
        const std::string& name,
        std::vector<Element>& elements) const;

    bool contains(const std::string& name) const;

    static bool parse(
        const std::string& path, 
        Element& root,
        Error& error);

private:
    std::string _name;
    Attributes _attrs;
    std::string _chars;
    std::vector<Element> _children;
};

#endif /* _DOX2MD_ELEMENT_H */
