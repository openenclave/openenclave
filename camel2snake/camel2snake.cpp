// Licensed under the MIT License.

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <cctype>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <cstdarg>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

typedef vector<char> Buffer;
typedef pair<string, string> Pair;
typedef map<string, string> Map;
typedef set<string> Set;

struct Conf
{
    Map replace;
    Map sub;
    Set ignore;
    Set prefix;
};

const char* arg0;

__attribute__((format(printf, 1, 2)))
void err(const char* format, ...)
{
    fprintf(stderr, "%s: ", arg0);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fputc('\n', stderr);
}

// Load a file into memory.
int load_file(const char* path, Buffer& buffer)
{
    int ret = -1;
    FILE* is = NULL;

    // Open the file.
    if (!(is = fopen(path, "rb")))
        goto done;

    // Read file into memory.
    {
        char buf[4096];
        size_t n;

        while ((n = fread(buf, sizeof(char), sizeof(buf), is)) > 1)
            buffer.insert(buffer.end(), buf, buf + n);
    }

    // Append a zero-terminator.
    buffer.push_back('\0');

    ret = 0;

done:

    if (is)
        fclose(is);

    return ret;
}

// Skip over C ident; return pointer past end of ident.
static const char* _parse_c_ident(const char* p)
{
    if (isalpha(*p) || *p == '_')
    {
        p++;

        while (isalnum(*p) || *p == '_')
            p++;
    }

    return p;
}

bool match_camel(const char* ident, const char* prefix)
{
    bool upper = false;
    bool lower = false;
    bool underscore = false;
    const char* p = ident;

    // Check prefix:
    {
        size_t n = strlen(prefix);

        if (strncmp(p, prefix, n) != 0)
            return false;

        p += n;
    }

    while (*p)
    {
        if (isalpha(*p) && isupper(*p))
            upper = true;
        else if (isalpha(*p) && islower(*p))
            lower = true;
        else if (*p == '_')
            underscore = true;

        p++;
    }

    return upper && lower && !underscore;
}

static const char* _skip_spaces(const char* p)
{
    while (isspace(*p))
        p++;

    return p;
}

static const char* _expect(const char* p, char c)
{
    while (isspace(*p))
        p++;

    if (*p++ != c)
        return NULL;

    while (isspace(*p))
        p++;

    return p;
}

static const char* _expect_c_ident(const char* p, string& ident)
{
    const char* start = p;

    p = _parse_c_ident(p);

    if (p == start)
        return NULL;

    ident.assign(start, p - start);
    return p;
}

int load_config(const char* path, Conf& conf)
{
    int ret = -1;
    FILE* is;
    char buf[1024];
    size_t line = 1;

    if (!(is = fopen(path, "r")))
        goto done;

    for (; fgets(buf, sizeof(buf), is) != NULL; line++)
    {
        const char* p = buf;
        char* end = (char*)p + strlen(p);
        string keyword;

        /* Remove leading space */
        while (*p && isspace(*p))
            p++;

        /* Skip comment line */
        if (*p == '#')
            continue;

        /* Remove trailing space */
        while (end != buf && isspace(end[-1]))
            *--end = '\0';

        /* Skip blank lines */
        if (*p == '\0')
            continue;

        /* Parse keyword */
        if (!(p = _expect_c_ident(p, keyword)))
            err("%s: %s:%zu: syntax", arg0, path, line);

        /* Parse keyword value */
        if (keyword == "replace")
        {
            string from;
            string to;

            if (!(p = _expect(p, '=')))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect_c_ident(p, from)))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect(p, ':')))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect_c_ident(p, to)))
                err("%s: %s:%zu: syntax", arg0, path, line);

            conf.replace.insert(Pair(from, to));
        }
        else if (keyword == "sub")
        {
            string from;
            string to;

            if (!(p = _expect(p, '=')))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect_c_ident(p, from)))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect(p, ':')))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect_c_ident(p, to)))
                err("%s: %s:%zu: syntax", arg0, path, line);

            conf.sub.insert(Pair(from, to));
        }
        else if (keyword == "prefix")
        {
            string value;

            if (!(p = _expect(p, '=')))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect_c_ident(p, value)))
                err("%s: %s:%zu: syntax", arg0, path, line);

            conf.prefix.insert(value);
        }
        else if (keyword == "ignore")
        {
            string value;

            if (!(p = _expect(p, '=')))
                err("%s: %s:%zu: syntax", arg0, path, line);

            if (!(p = _expect_c_ident(p, value)))
                err("%s: %s:%zu: syntax", arg0, path, line);

            conf.ignore.insert(value);
        }
        else
        {
            err("%s: %s:%zu: unknown keyword: %s", arg0, path, line,
                keyword.c_str());
        }
    }

    ret = 0;

done:

    if (is)
        fclose(is);

    return ret;
}

static string _camel_to_snake(const string& s)
{
    string snake;
    bool prev_is_lower = false;

    for (size_t i = 0; i < s.size(); i++)
    {
        if (isupper(s[i]))
        {
            if (prev_is_lower)
            {
                snake += '_';
                snake += tolower(s[i]);
            }
            else
            {
                snake += tolower(s[i]);
            }
        }
#if 0
        else if (i > 2 && islower(s[i]) && isupper(s[i-1]) && isupper(s[i-2]))
        {
            // XYAbc => xy_abc
            //    ^
            // snake=xya
            char c = snake[snake.size()-1];
            snake[snake.size()-1] = '_';
            snake += c;
            snake += s[i];
        }
#endif
        else
        {
            snake += s[i];
        }

        prev_is_lower = islower(s[i]);
    }

    return snake;
}

int find_typedefs(const char* path, Set& typedefs)
{
    int ret = -1;
    FILE* os = NULL;
    Buffer buffer;

    // Load the input source file.
    if (load_file(path, buffer) != 0)
    {
        err("failed to load file: %s", path);
        goto done;
    }

    // Parse the file:
    for (const char* p = &buffer[0]; *p; )
    {
        const char* start = p;
        p = _parse_c_ident(start);

        if (p == start)
        {
            p++;
        }
        else
        {
            string tok1(start, p - start);

            if (tok1 == "typedef")
            {
                p = _skip_spaces(p);
                p = _parse_c_ident(start = p);

                if (p != start)
                {
                    string tok2(start, p - start);

                    if (tok2 == "struct" || tok2 == "enum")
                    {
                        p = _skip_spaces(p);
                        p = _parse_c_ident(start = p);

                        if (p != start)
                        {
                            string name(start, p - start);

                            if (name[0] == '_')
                                name = name.substr(1);
                            
                            typedefs.insert(name);
                        }
                    }
                }
            }
        }
    }

    ret = 0;

done:

    if (os)
        fclose(os);

    return ret;
}

void _apply_substitutions(string& snake, const Map& sub)
{
    Map::const_iterator p = sub.begin();
    Map::const_iterator end = sub.end();

    while (p != end)
    {
        const string& from = (*p).first;
        const string& to = (*p).second;

        size_t pos = snake.find(from);

        if (pos != string::npos)
            snake.replace(pos, from.size(), to);

        p++;
    }
}

int camel2snake(
    const char* path, 
    const Conf& conf, 
    Set& typedefs,
    Map& log)
{
    int ret = -1;
    FILE* os = NULL;
    Buffer buffer;
    vector<char> out;

    // Load the input source file.
    if (load_file(path, buffer) != 0)
    {
        err("failed to load file: %s", path);
        goto done;
    }

    // Parse the file:
    for (const char* p = &buffer[0]; *p; )
    {
        const char* start = p;
        p = _parse_c_ident(start);

        if (p == start)
        {
            out.push_back(*p++);
        }
        else
        {
            string ident(start, p - start);
            string snake;

            Set::const_iterator pp = conf.prefix.begin();
            Set::const_iterator ppend = conf.prefix.end();

            while (pp != ppend)
            {
                string prefix = *pp;

                if (match_camel(ident.c_str(), prefix.c_str()))
                {
                    /* If identifer is not on the ignore list */
                    if (conf.ignore.find(ident) == conf.ignore.end())
                    {
                        /* Check first for manual replacement */
                        Map::const_iterator replace = conf.replace.find(ident);

                        if (replace == conf.replace.end())
                        {
                            snake = _camel_to_snake(ident);
                            break;
                        }
                        else
                        {
                            snake = (*replace).second;
                            break;
                        }
                    }
                }
                else
                {
                    if (conf.ignore.find(ident) == conf.ignore.end())
                    {
                        Map::const_iterator replace = conf.replace.find(ident);

                        if (replace != conf.replace.end())
                        {
                            snake = (*replace).second;
                            break;
                        }
                    }
                }

                pp++;
            }

            if (snake.size())
            {
                if (typedefs.find(ident) != typedefs.end())
                    snake += "_t";

                _apply_substitutions(snake, conf.sub);

                log.insert(Pair(ident, snake));

                out.insert(out.end(), &snake[0], &snake[0] + snake.size());
            }
            else
            {
                string tmp = ident;
                _apply_substitutions(tmp, conf.sub);

                if (ident != tmp)
                {
                    log.insert(Pair(ident, tmp));
                    ident = tmp;
                }

                out.insert(out.end(), &ident[0], &ident[0] + ident.size());
            }
        }
    }

    /* Rewrite the file */
    {
        if (!(os = fopen(path, "w")))
            goto done;

        if (fwrite(&out[0], 1, out.size(), os) != out.size())
            goto done;
    }

    ret = 0;

done:

    if (os)
        fclose(os);

    return ret;
}

int main(int argc, const char* argv[])
{
    int ret = 1;
    arg0 = argv[0];
    Conf conf;
    Set typedefs;
    Map log;
    FILE* os = NULL;

    // Check parameters:
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s sources\n", argv[0]);
        goto done;
    }

    // Read the configuration file:
    {
        const char path[] = "camel2snake.conf";

        if (load_config(path, conf) != 0)
        {
            err("failed to load: %s", path);
            goto done;
        }
    }

    // Compile list of typedefs:
    for (int i = 1; i < argc; i++)
    {
        if (find_typedefs(argv[i], typedefs) != 0)
        {
            err("failed: %s", argv[i]);
            goto done;
        }
    }

    // Handle each file:
    for (int i = 1; i < argc; i++)
    {
        if (camel2snake(argv[i], conf, typedefs, log) != 0)
        {
            err("failed: %s", argv[i]);
            goto done;
        }
    }

    // Write the log:
    {
        const char path[] = "camel2snake.log";

        if (!(os = fopen(path, "w")))
        {
            err("failed to open %s", path);
            goto done;
        }

        unsigned int width = 0;
        {
            Map::const_iterator p = log.begin();
            Map::const_iterator end = log.end();

            while (p != end)
            {
                const string& camel = (*p).first;

                if (camel.size() > width)
                    width = camel.size();
                p++;
            }
        }

        {
            Map::const_iterator p = log.begin();
            Map::const_iterator end = log.end();

            while (p != end)
            {
                const string& camel = (*p).first;
                const string& snake = (*p).second;
                fprintf(os, "%-*s => %s\n", width, camel.c_str(), 
                    snake.c_str());
                p++;
            }
        }
    }

    ret = 0;

done:

    return ret;
}
