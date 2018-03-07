// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "lexer.h"
#include <ctype.h>

Tok Lexer::_Next()
{
    Tok tok = TOK_ERR;

    /* Skip whitespace */
    while (isspace(*_p))
    {
        if (*_p == '\n')
            _line++;

        _p++;
    }

    /* End of file? */
    if (*_p == '\0')
    {
        tok = TOK_EOF;
        goto done;
    }

    /* Skip C-style comment */
    if (_p[0] == '/' && _p[1] == '*')
    {
        _p += 2;

        while (*_p)
        {
            if (*_p == '\n')
                _line++;

            if (_p[0] == '*' && _p[1] == '/')
            {
                _p += 2;

                if (this->SetText("/* comment */", 13) != 0)
                    goto done;

                tok = this->tok = TOK_COMMENT;
                goto done;
            }

            _p++;
        }

        /* Closing comment not found */
        goto done;
    }

    /* Skip C++-style comment */
    if (_p[0] == '/' && _p[1] == '/')
    {
        _p += 2;

        while (*_p)
        {
            if (*_p == '\n')
            {
                _p++;
                _line++;
                break;
            }

            _p++;
        }

        if (this->SetText("// comment", 10) != 0)
            goto done;

        tok = this->tok = TOK_COMMENT;
        goto done;
    }

    /* Identifier: "[A-Za-z][A-Za-z0-9]*" */
    if (isalpha(*_p) || *_p == '_')
    {
        const char* start = _p++;

        while (isalnum(*_p) || *_p == '_')
            _p++;

        if (this->SetText(start, _p - start) != 0)
            goto done;

        /* Determine token type */
        if (strcmp(this->text, "const") == 0)
            tok = this->tok = TOK_CONST;
        else if (strcmp(this->text, "include") == 0)
            tok = this->tok = TOK_INCLUDE;
        else if (strcmp(this->text, "verbatim") == 0)
            tok = this->tok = TOK_VERBATIM;
        else if (strcmp(this->text, "struct") == 0)
            tok = this->tok = TOK_STRUCT;
        else if (strcmp(this->text, "function") == 0)
            tok = this->tok = TOK_FUNCTION;
        else if (strcmp(this->text, "unsigned") == 0)
            tok = this->tok = TOK_UNSIGNED;
        else if (strcmp(this->text, "signed") == 0)
            tok = this->tok = TOK_SIGNED;
#if 0
        else if (strcmp(this->text, "long") == 0)
            tok = this->tok = TOK_LONG;
#endif
        else
            tok = this->tok = TOK_IDENTIFIER;

        goto done;
    }

    /* Number: "[0-9]*" */
    if (isdigit(*_p))
    {
        const char* start = _p++;

        while (isdigit(*_p))
            _p++;

        if (this->SetText(start, _p - start) != 0)
            goto done;

        tok = this->tok = TOK_NUMBER;
        goto done;
    }

    /* String literal: ["..."] */
    if (*_p == '"')
    {
        const char* start = _p++;

        while (*_p && *_p != '"')
            _p++;

        if (*_p != '"')
        {
            this->SetErr("unterminated string literal");
            goto done;
        }

        _p++;

        if (this->SetText(start, _p - start) != 0)
            goto done;

        tok = this->tok = TOK_STRING;
        goto done;
    }

    /* Handle character tokens */
    switch (*_p)
    {
        case '*':
            tok = TOK_PTR;
            break;
        case '[':
            tok = TOK_OPEN_BRACKET;
            break;
        case ']':
            tok = TOK_CLOSE_BRACKET;
            break;
        case '(':
            tok = TOK_OPEN_PAREN;
            break;
        case ')':
            tok = TOK_CLOSE_PAREN;
            break;
        case '{':
            tok = TOK_OPEN_BRACE;
            break;
        case '}':
            tok = TOK_CLOSE_BRACE;
            break;
        case ';':
            tok = TOK_SEMICOLON;
            break;
        case ',':
            tok = TOK_COMMA;
            break;
        case '=':
            tok = TOK_EQUAL;
            break;
    }

    if (tok != TOK_ERR)
    {
        if (this->SetText(_p++, 1) != 0)
            goto done;

        this->tok = tok;
    }

done:

    return tok;
}

Lexer::Lexer()
{
    Clear();
}

Lexer::Lexer(const char* file, const char* data)
{
    Init(file, data);
}

void Lexer::Swap(Lexer& x)
{
    char tmp[sizeof(Lexer)];
    memcpy(tmp, this, sizeof(Lexer));
    memcpy(this, &x, sizeof(Lexer));
    memcpy(&x, tmp, sizeof(Lexer));
}

void Lexer::Init(const char* file, const char* data)
{
    Clear();
    _file = file;
    _line = 1;
    _data = data;
    _p = _data;
    tok = TOK_EOF;
}

void Lexer::Clear()
{
    memset(this, 0, sizeof(Lexer));
}

int Lexer::SetText(const char* text_, size_t len)
{
    if (len >= sizeof(text))
        return -1;

    text[0] = '\0';
    strncat(text, text_, len);
    return 0;
}

OE_PRINTF_FORMAT(2, 3)
void Lexer::SetErr(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(_error, sizeof(_error), format, ap);
    va_end(ap);
}

void Lexer::PutErr() const
{
    fprintf(stderr, "%s(%u): %s\n", _file, _line, _error);
}

Tok Lexer::Next()
{
    Tok tok;

    while ((tok = _Next()) == TOK_COMMENT)
        ;

    return tok;
}
