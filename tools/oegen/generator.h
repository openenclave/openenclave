#ifndef _OE_GENERATOR_H
#define _OE_GENERATOR_H

#include <iostream>
#include "objects.h"

class Generator
{
  public:
    static int
    GenerateSourceFile(std::ostream& os, const std::string& path, bool trusted, const std::vector<Object*>& objects);

    static int
    GenerateHeaderFile(std::ostream& os, const std::string& path, bool trusted, const std::vector<Object*>& objects);
};

#endif /* _OE_GENERATOR_H */
