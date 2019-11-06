// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

extern int main_shared(int argc, const char* argv[]);

int main(int argc, const char* argv[])
{
    return main_shared(argc, argv);
}
