#include <cstdio>
#include <cstdlib>
#include <fstream>
#include "files.h"
#include "generator.h"
#include "lexer.h"
#include "objects.h"
#include "parser.h"

const char* arg0;

using namespace std;

OE_PRINTF_FORMAT(1, 2)
static void ErrExit(const char* format, ...)
{
    fprintf(stderr, "%s: ", arg0);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static string StripDirectory(const string& path)
{
    size_t pos = path.rfind("/");

    if (pos == string::npos)
        return path;
    else
        return path.substr(pos + 1);
}

static bool HasExtension(const string& path, const string& ext)
{
    // Find extension within path:
    size_t npos = path.rfind(ext);
    if (npos == string::npos)
        return false;

    // If path does not end with extension:
    if (npos + ext.size() != path.size())
        return false;

    return true;
}

static string StripExtension(const string& path, const string& ext)
{
    // Find extension within path:
    size_t npos = path.rfind(ext);
    if (npos == string::npos)
        return path;

    // If path does not end with extension:
    if (npos + ext.size() != path.size())
        return path;

    return path.substr(0, npos);
}

int GetOpt(int& argc, const char* argv[], const char* name, const char** arg = NULL)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            if (!arg)
            {
                memmove((void*)&argv[i], &argv[i + 1], (argc - i) * sizeof(char*));
                argc--;
                return 1;
            }

            if (i + 1 == argc)
                return -1;

            *arg = argv[i + 1];
            memmove((char**)&argv[i], &argv[i + 2], (argc - i - 1) * sizeof(char*));
            argc -= 2;
            return 1;
        }
    }

    return 0;
}

const char HELP[] = "Usage: %s OPTIONS IDL-FILENAME\n"
                    "\n"
                    "OPTIONS:\n"
                    "    -t, --trusted    - generate trusted sources (enclave).\n"
                    "    -u, --untrusted  - generate untrusted sources (application).\n"
                    "    -d, --dir PATH   - directory where sources are written.\n"
                    "    -h, --help       - print this help message.\n"
                    "\n";

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    string idlFile;

    // Print help message?
    if (GetOpt(argc, argv, "-h") == 1 || GetOpt(argc, argv, "--help") == 1)
    {
        fprintf(stderr, HELP, arg0);
        return 1;
    }

    // Get trusted option:
    bool trusted = false;
    if (GetOpt(argc, argv, "-t") == 1 || GetOpt(argc, argv, "--trusted") == 1)
        trusted = true;

    // Get untrusted option:
    bool untrusted = false;
    if (GetOpt(argc, argv, "-u") == 1 || GetOpt(argc, argv, "--untrusted") == 1)
        untrusted = true;

    // Get the directory:
    string dirname;
    {
        const char* arg = NULL;

        if (GetOpt(argc, argv, "-d", &arg) == 1 || GetOpt(argc, argv, "--dir", &arg) == 1)
        {
            dirname = arg;

            if (dirname.size() && dirname[dirname.size() - 1] != '/')
                dirname += '/';
        }
    }

    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, HELP, arg0);
        return 1;
    }

    // Check -t and -u options:
    if (!trusted && !untrusted)
    {
        ErrExit("specify --trusted or --untrusted");
        return 1;
    }

    // Check -t and -u options:
    if (trusted && untrusted)
    {
        ErrExit("--trusted and --untrusted are incompatible (pick one)");
        return 1;
    }

    // Collectd arguments:
    idlFile = argv[1];

    // Load the IDL file into memory:
    vector<char> data;
    if (LoadFile(idlFile.c_str(), 1, data) != 0)
        ErrExit("failed to load '%s'", idlFile.c_str());

    // Create lexer instance:
    Lexer lexer(idlFile.c_str(), &data[0]);

    // Initialize the parser:
    Parser parser;
    if (parser.Parse(lexer) != 0)
        ErrExit("parse failed\n");

    // IDL file must have .edl extension:
    if (!HasExtension(idlFile, ".idl"))
        ErrExit("%s does not have an '.idl' extension", idlFile.c_str());

    // Get filename without directory and without the '.idl' extension:
    string filename = StripExtension(StripDirectory(idlFile), ".idl");

    // Generate trusted sources:
    if (trusted)
    {
        // Generate trusted header file:
        {
            string path = dirname + filename + "_t.h";
            ofstream os(path.c_str());

            if (!os)
                ErrExit("failed to open: %s", path.c_str());

            if (Generator::GenerateHeaderFile(os, path, true, parser.Objects()) != 0)
            {
                ErrExit("failed to generate: %s", path.c_str());
            }

            cout << "Created " << path << endl;
        }

        // Generate trusted source file:
        {
            string path = dirname + filename + "_t.c";
            ofstream os(path.c_str());

            if (!os)
                ErrExit("failed to open: %s", path.c_str());

            if (Generator::GenerateSourceFile(os, path, true, parser.Objects()) != 0)
            {
                ErrExit("failed to generate: %s", path.c_str());
            }

            cout << "Created " << path << endl;
        }
    }

    // Generate untrusted sources:
    if (untrusted)
    {
        // Generate untrusted header file:
        {
            string path = dirname + filename + "_u.h";
            ofstream os(path.c_str());

            if (!os)
                ErrExit("failed to open: %s", path.c_str());

            if (Generator::GenerateHeaderFile(os, path, false, parser.Objects()) != 0)
            {
                ErrExit("failed to generate: %s", path.c_str());
            }

            cout << "Created " << path << endl;
        }

        // Generate untrusted source file:
        {
            string path = dirname + filename + "_u.c";
            ofstream os(path.c_str());

            if (!os)
                ErrExit("failed to open: %s", path.c_str());

            if (Generator::GenerateSourceFile(os, path, false, parser.Objects()) != 0)
            {
                ErrExit("failed to generate: %s", path.c_str());
            }

            cout << "Created " << path << endl;
        }
    }

    return 0;
}
