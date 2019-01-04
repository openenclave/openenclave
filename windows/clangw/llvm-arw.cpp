// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <string>

int main(int argc, char** argv)
{
    // Loop through each argument and transform \ to /.
    std::string cmd = "llvm-ar";
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        std::replace(arg.begin(), arg.end(), '\\', '/');

        // If a response file is specified, transform slashes
        // within the response file.
        if (arg[0] == '@')
        {
            // Fix up directory separators in the response file
            std::string fixup = "bash -c \"sed -i 's/\\\\\\\\/\\//g' ";
            fixup += arg.substr(1) + "\"";
            printf("cmd = %s\n", fixup.c_str());
            system(fixup.c_str());
        }
        cmd += " ";
        cmd += arg;
    }
    // Call llvm-ar
    return system(cmd.c_str());
}
