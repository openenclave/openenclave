// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/cert.h>
#include <openenclave/bits/files.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/raise.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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
    exit(1);
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

OE_Result CountCerts(const uint8_t* data, size_t size, size_t* length)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertChain chain;

    /* Load the chain */
    if (OE_CertChainReadPEM(data, size, &chain) != OE_OK)
        OE_RAISE(OE_FAILURE);

    /* Get the length of the chain */
    if (OE_CertChainGetLength(&chain, length))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    OE_CertChainFree(&chain);

    return result;
}

static void Indent(size_t level)
{
    for (size_t i = 0; i < level; i++)
        printf("    ");
}

void DumpRSAPublicKey(const OE_RSAPublicKey* key, size_t level)
{
    OE_Result r;

    Indent(level);
    printf("RSAPublicKey\n");

    Indent(level);
    printf("{\n");
    level++;

    /* Print the modulus */
    {
        uint8_t* buffer = NULL;
        size_t bufferSize = 0;

        /* Required buffer size */
        r = OE_RSAPublicKeyGetModulus(key, NULL, &bufferSize);

        if (r != OE_BUFFER_TOO_SMALL)
            err("OE_RSAGetPublicKeyBytes() failed 1");

        if (!(buffer = (uint8_t*)malloc(bufferSize)))
            err("malloc() failed");

        /* Get the key bytes */
        if (OE_RSAPublicKeyGetModulus(key, buffer, &bufferSize) != OE_OK)
            err("OE_RSAGetPublicKeyBytes() failed 2");

        Indent(level);
        printf("modulus=");
        OE_HexDump(buffer, bufferSize);
    }

    /* Print the exponent */
    {
        uint8_t* buffer = NULL;
        size_t bufferSize = 0;

        /* Required buffer size */
        r = OE_RSAPublicKeyGetExponent(key, NULL, &bufferSize);

        if (r != OE_BUFFER_TOO_SMALL)
            err("OE_RSAGetPublicKeyBytes() failed 1");

        if (!(buffer = (uint8_t*)malloc(bufferSize)))
            err("malloc() failed");

        /* Get the key bytes */
        if (OE_RSAPublicKeyGetExponent(key, buffer, &bufferSize) != OE_OK)
            err("OE_RSAGetPublicKeyBytes() failed 2");

        Indent(level);
        printf("exponent=");
        OE_HexDump(buffer, bufferSize);
    }

    level--;
    Indent(level);
    printf("}\n");
}

void DumpECPublicKey(const OE_ECPublicKey* key, size_t level)
{
    uint8_t* buffer = NULL;
    size_t bufferSize = 0;
    OE_Result r;

    Indent(level);
    printf("ECPublicKey\n");

    Indent(level);
    printf("{\n");
    level++;

    /* Get the key bytes */
    {
        /* Required buffer size */
        r = OE_ECPublicKeyGetKeyBytes(key, NULL, &bufferSize);

        if (r != OE_BUFFER_TOO_SMALL)
            err("OE_ECPublicKeyGetKeyBytes() failed 1");

        if (!(buffer = (uint8_t*)malloc(bufferSize)))
            err("malloc() failed");

        /* Get the key bytes */
        if (OE_ECPublicKeyGetKeyBytes(key, buffer, &bufferSize) != OE_OK)
            err("OE_ECPublicKeyGetKeyBytes() failed 2");
    }

    Indent(level);
    printf("key=");
    OE_HexDump(buffer, bufferSize);

    level--;
    Indent(level);
    printf("}\n");
}

void DumpCert(const OE_Cert* cert, size_t level)
{
    Indent(level);
    printf("OE_Cert\n");

    Indent(level);
    printf("{\n");
    level++;

    /* Print the subject name */
    {
        char* name = NULL;
        size_t size;

        /* Determine the buffer size */
        if (OE_CertGetSubjectName(cert, NULL, &size) != OE_BUFFER_TOO_SMALL)
            err("OE_CertGetSubjectName() failed");

        /* Allocate buffer space */
        if (!(name = (char*)malloc(size)))
            err("malloc() failed");

        /* Get the subject name */
        if (OE_CertGetSubjectName(cert, name, &size) != OE_OK)
            err("OE_CertGetSubjectName() failed");

        Indent(level);
        printf("subject=%s\n", name);
        free(name);
    }

    /* Print the RSA public key (if any) */
    {
        OE_RSAPublicKey key;

        if (OE_CertGetRSAPublicKey(cert, &key) == OE_OK)
            DumpRSAPublicKey(&key, level);
    }

    /* Print the EC public key (if any) */
    {
        OE_ECPublicKey key;

        if (OE_CertGetECPublicKey(cert, &key) == OE_OK)
            DumpECPublicKey(&key, level);
    }

    level--;
    Indent(level);
    printf("}\n");
}

void DumpCertChain(const OE_CertChain* chain)
{
    size_t length;

    /* Get the number of certificates in this chain */
    if (OE_CertChainGetLength(chain, &length) != OE_OK)
        err("OE_CertChainGetLength() failed");

    printf("OE_CertChain\n");
    printf("{\n");

    for (uint32_t i = 0; i < length; i++)
    {
        OE_Cert cert;

        if (OE_CertChainGetCert(chain, i, &cert) != OE_OK)
            DumpCert(&cert, 1);
    }

    printf("}\n");
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    int ret = -1;
    uint8_t* data = NULL;
    size_t size;
    size_t numCerts;

    /* Check command-line arguments */
    if (argc != 2)
    {
        fprintf(stderr, usage, argv[0]);
        goto done;
    }

    /* Load the file into memory */
    {
        if (__OE_LoadFile(argv[1], 1, (void**)&data, &size) != OE_OK)
            err("failed to load certificate file: %s", argv[1]);

        if (size)
            data[size - 1] = '\0';
    }

    /* Determine whether a certificate chain */
    if (CountCerts(data, size, &numCerts) != OE_OK)
        err("failed to read certificate(s) from PEM data");

    /* If this contains more than one certificate then dump the chain */
    if (numCerts > 1)
    {
        OE_CertChain chain;

        if (OE_CertChainReadPEM(data, size, &chain) != OE_OK)
            err("OE_CertChainReadPEM() failed");

        DumpCertChain(&chain);
    }
    else
    {
        OE_Cert cert;

        if (OE_CertReadPEM(data, size, &cert) != OE_OK)
            err("OE_CertReadPEM() failed");

        DumpCert(&cert, 0);
    }

    ret = 0;

done:

    if (data)
        free(data);

    return ret;
}
