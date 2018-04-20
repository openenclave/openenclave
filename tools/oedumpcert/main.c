#include <openenclave/bits/cert.h>
#include <openenclave/bits/files.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

const char* arg0;

OE_PRINTF_FORMAT(1, 2)
void err(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "*** Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

const char usage[] =
"Usage: %s <CertificateFile>\n"
"\n"
"Where:\n"
"    <CertificateFile> is the name of a certificate file in PEM format.\n"
"\n"
"Synopsis:\n"
"    This utility dumps information about the given certificate to\n"
"    standard output. The certificate must be in PEM format, bearing\n"
"    the following PEM header and footer lines.\n"
"\n"
"        -----BEGIN CERTIFICATE-----\n"
"        -----END CERTIFICATE-----\n"
"\n"
"    Any SGX-specific content (if any) is also dumped.\n"
"\n";

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    int ret = -1;
    OE_Result result;
    uint8_t* data = NULL;
    size_t size;
    OE_Cert cert;

    /* Check command-line arguments */
    if (argc != 2)
    {
        fprintf(stderr, usage, argv[0]);
        goto done;
    }

    /* Load the file into memory */
    if (__OE_LoadFile(argv[1], 1, (void**)&data, &size) != OE_OK)
        err("failed to load certificate file: %s", argv[1]);

    if (size)
        data[size-1] = '\0';

    /* Load the certificate */
    if ((result = OE_CertReadPEM(data, size, &cert)) != OE_OK)
        err("failed to read PEM data");

    ret = 0;

done:

    if (data)
        free(data);

    return ret;
}
