#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

int LoadFile(const string& path, vector<unsigned char>& v)
{
    ifstream is(path.c_str());

    if (!is)
        return -1;

    char c;

    while (is.get(c))
        v.push_back(c);

    return 0;
}

#define _OE_ENCLAVE_H
#include "../../enclave/certificate.c"

int main(int argc, const char* argv[])
{
    int ret = 1;
    vector<unsigned char> certData;
    vector<unsigned char> chainData;
    OE_Result result;
    OE_VerifyCertificateError error;

    // Check arguments:
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s cert chain\n", argv[0]);
        goto done;
    }

    if (LoadFile(argv[1], certData) != 0)
    {
        fprintf(stderr, "failed to load: %s\n", argv[1]);
        exit(1);
    }

    certData.push_back('\0');

    if (LoadFile(argv[2], chainData) != 0)
    {
        fprintf(stderr, "failed to load: %s\n", argv[2]);
        exit(1);
    }

    chainData.push_back('\0');

    result = OE_VerifyCertificate(
        (const char*)&certData[0], (const char*)&chainData[0], &error);

    if (result != OE_OK)
    {
        printf("%s: verify failed: %s\n", argv[0], error.buf);
        exit(0);
    }

    printf("%s: verify ok\n", argv[0]);
    ret = 0;

done:
    exit(ret);
}
