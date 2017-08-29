#ifndef _OE_PARSER_H
#define _OE_PARSER_H

#include "objects.h"
#include "lexer.h"

class Parser
{
public:

    Parser();

    ~Parser();

    void Clear();

    void Dump() const;

    int Parse(Lexer& lexer);

    const std::vector<Object*>& Objects() const;

private:
    std::vector<Object*> _objects;
};

#endif /* _OE_PARSER_H */
