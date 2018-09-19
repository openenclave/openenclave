// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_LEXER_H
#define _OE_LEXER_H

#include <openenclave/host.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define LEXER_MAX_TEXT_SIZE 1024
#define LEXER_MAX_ERROR_SIZE 1024

enum Tok
{
    TOK_ERR = -1,
    TOK_EOF = 0,
    TOK_IDENTIFIER,
    TOK_CONST,
    TOK_VERBATIM,
    TOK_INCLUDE,
    TOK_FUNCTION,
    TOK_STRUCT,
    TOK_SIGNED,
    TOK_UNSIGNED,
    TOK_COMMENT,
    TOK_NUMBER,
    TOK_STRING,
    TOK_PTR,
    TOK_OPEN_BRACKET,
    TOK_CLOSE_BRACKET,
    TOK_OPEN_PAREN,
    TOK_CLOSE_PAREN,
    TOK_OPEN_BRACE,
    TOK_CLOSE_BRACE,
    TOK_SEMICOLON,
    TOK_COMMA,
    TOK_EQUAL,
    // TOK_LONG,
};

struct Lexer
{
    Tok tok;
    char text[LEXER_MAX_TEXT_SIZE];

    Lexer();

    Lexer(const char* file, const char* data);

    void Swap(Lexer& x);

    void Init(const char* file, const char* data);

    void Clear();

    int SetText(const char* text, size_t len);

    OE_PRINTF_FORMAT(2, 3)
    void SetErr(const char* format, ...);

    void PutErr() const;

    bool TestErr() const
    {
        return _error[0];
    }

    Tok Next();

    unsigned int GetLine() const
    {
        return _line;
    }

  private:
    Tok _next();

    const char* _file;
    unsigned int _line;
    const char* _data;
    const char* _p;
    char _error[LEXER_MAX_ERROR_SIZE];
};

#endif /* _OE_LEXER_H */
