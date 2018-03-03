// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

using namespace std;

const char* arg0;

set<string> ignores;

bool IsBinFile(const string& path)
{
    FILE* is;
    int c;

    if (!(is = fopen(path.c_str(), "rb")))
    {
        cerr << arg0 << ": failed to open " << path << endl;
        exit(0);
    }

    while ((c = fgetc(is)) != EOF)
    {
        if (c >= 128)
        {
            fclose(is);
            return true;
        }
    }

    fclose(is);
    return false;
}

void FindBins(const string& root)
{
    DIR* dir;
    vector<string> dirs;

    // Ignore this directory?
    if (ignores.find(root) != ignores.end())
        return;

    if (!(dir = opendir(root.c_str())))
    {
        cerr << arg0 << ": warning: failed to open " << root << endl;
        return;
    }

    struct dirent* ent;

    while ((ent = readdir(dir)))
    {
        string name = ent->d_name;

        if (name == "." || name == "..")
            continue;

        string path = root + "/" + name;

        // Ignore this file?
        if (ignores.find(path) != ignores.end())
            continue;

        if (IsBinFile(path))
            cout << path << endl;

        if (ent->d_type == DT_DIR)
            dirs.push_back(path);
    }

    closedir(dir);

    for (size_t i = 0; i < dirs.size(); i++)
        FindBins(dirs[i]);
}

void ReadIgnores()
{
    FILE* is;
    char line[4096];

    if (!(is = fopen(".binsignore", "rb")))
        return;

    while ((fgets(line, sizeof(line), is) != NULL))
    {
        char* p = line;
        char* end;

        // Skip leading whitespace:
        while (isspace(*p))
            p++;

        // Ignore comments:
        if (*p == '#')
            continue;

        // Seek end of string:
        for (end = p; *end; end++)
            ;

        // Remove trailing whitespace:
        while (end != p && isspace(end[-1]))
            *--end = '\0';

        ignores.insert(line);
    }

    fclose(is);
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];

    if (argc != 1)
    {
        cerr << "Usage: " << argv[0] << endl;
        exit(1);
    }

    // Read .binsignore file:
    ReadIgnores();

    // Find all binaries relative to this directory:
    FindBins(".");

    return 0;
}
