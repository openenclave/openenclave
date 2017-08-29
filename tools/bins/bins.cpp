#include <sys/types.h>
#include <dirent.h>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

const char* arg0;

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

    if (!(dir = opendir(root.c_str())))
    {
        cerr << arg0 << ": failed to open " << root << endl;
        exit(1);
    }

    struct dirent* ent;

    while ((ent = readdir(dir)))
    {
        string name = ent->d_name;

        if (name == "." || name == "..")
            continue;

        string path = root + "/" + name;

        if (IsBinFile(path))
            cout << path << endl;

        if (ent->d_type == DT_DIR)
            dirs.push_back(path);
    }

    closedir(dir);

    for (size_t i = 0; i < dirs.size(); i++)
        FindBins(dirs[i]);
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];

    if (argc != 1)
    {
        cerr << "Usage: " << argv[0] << endl;
        exit(1);
    }

    FindBins(".");

    return 0;
}
