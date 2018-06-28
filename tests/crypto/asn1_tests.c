// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/asn1.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/tests.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"

static const char _CERT[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEejCCBCCgAwIBAgIVAIRhkz/I2bp4OHxNAneNMrWoyuVBMAoGCCqGSM49BAMC\n"
    "MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK\n"
    "DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\n"
    "BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xODA1MzAxMTMzMDVaFw0yNTA1MzAxMTMz\n"
    "MDVaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV\n"
    "BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG\n"
    "A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
    "Ej9Bl3EbeGMpTB8k4jeXrzNXWR7lT1PcpBOX6GQx49jmsqSGGPcUxPm91wU/RlMR\n"
    "rv5GyfrrZ908wDaXTtfezKOCApQwggKQMB8GA1UdIwQYMBaAFOW7Uo+A+eMzrhms\n"
    "+mNGeBHzYbukMFgGA1UdHwRRME8wTaBLoEmGR2h0dHBzOi8vY2VydGlmaWNhdGVz\n"
    "LnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vSW50ZWxTR1hQQ0tQcm9jZXNzb3Iu\n"
    "Y3JsMB0GA1UdDgQWBBQcmM3b/dX0Stal0ynHbWpCzwvs8TAOBgNVHQ8BAf8EBAMC\n"
    "BsAwDAYDVR0TAQH/BAIwADCCAdQGCSqGSIb4TQENAQSCAcUwggHBMB4GCiqGSIb4\n"
    "TQENAQEEEB+MHnumvRB9hCTdNWSdzXIwggFkBgoqhkiG+E0BDQECMIIBVDAQBgsq\n"
    "hkiG+E0BDQECAQIBBDAQBgsqhkiG+E0BDQECAgIBBDAQBgsqhkiG+E0BDQECAwIB\n"
    "AjAQBgsqhkiG+E0BDQECBAIBBDAQBgsqhkiG+E0BDQECBQIBATARBgsqhkiG+E0B\n"
    "DQECBgICAIAwEAYLKoZIhvhNAQ0BAgcCAQAwEAYLKoZIhvhNAQ0BAggCAQAwEAYL\n"
    "KoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAwEAYLKoZIhvhNAQ0BAgsC\n"
    "AQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0BAg0CAQAwEAYLKoZIhvhN\n"
    "AQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYLKoZIhvhNAQ0BAhACAQAwEAYL\n"
    "KoZIhvhNAQ0BAhECAQUwHwYLKoZIhvhNAQ0BAhIEEAQEAgQBgAAAAAAAAAAAAAAw\n"
    "EAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhNAQ0BBAQGAJBuoQAAMA8GCiqGSIb4\n"
    "TQENAQUKAQAwCgYIKoZIzj0EAwIDSAAwRQIgPAfNJa59vmzOLdW5yWPo+OShrN7A\n"
    "sdbXaGu2gpAEqy8CIQCvie4k/cstz6V5A4T4Ks6fkDn22tWDTxtV+wepBReC2g==\n"
    "-----END CERTIFICATE-----\n";

static int _printf(char** str, const char* format, ...)
{
    char buf[1024];

    if (!str)
        return -1;

    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    if (n >= sizeof(buf))
        return -1;

    size_t size = n + 1;

    if (*str)
    {
        size += strlen(*str);

        if (!(*str = realloc(*str, size)))
            return -1;

        strcat(*str, buf);
    }
    else
    {
        if (!(*str = malloc(size)))
            return -1;

        strcpy(*str, buf);
    }

    return 0;
}

static void _indent(char** str, size_t depth)
{
    for (size_t i = 0; i < depth; i++)
        _printf(str, "    ");
}

static void _hex_dump(char** str, const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        _printf(str, "%02x", data[i]);
}

static const char _PARSE_OUTPUT[] =
    "SEQUENCE: length=1c1\n"
    "    SEQUENCE: length=1e\n"
    "        OID: 1.2.840.113741.1.13.1.1\n"
    "        OCTET_STRING:\n"
    "            length=10\n"
    "            data=1f8c1e7ba6bd107d8424dd35649dcd72\n"
    "    SEQUENCE: length=164\n"
    "        OID: 1.2.840.113741.1.13.1.2\n"
    "        SEQUENCE: length=154\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.1\n"
    "                INTEGER: value=4\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.2\n"
    "                INTEGER: value=4\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.3\n"
    "                INTEGER: value=2\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.4\n"
    "                INTEGER: value=4\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.5\n"
    "                INTEGER: value=1\n"
    "            SEQUENCE: length=11\n"
    "                OID: 1.2.840.113741.1.13.1.2.6\n"
    "                INTEGER: value=128\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.7\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.8\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.9\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.10\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.11\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.12\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.13\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.14\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.15\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.16\n"
    "                INTEGER: value=0\n"
    "            SEQUENCE: length=10\n"
    "                OID: 1.2.840.113741.1.13.1.2.17\n"
    "                INTEGER: value=5\n"
    "            SEQUENCE: length=1f\n"
    "                OID: 1.2.840.113741.1.13.1.2.18\n"
    "                OCTET_STRING:\n"
    "                    length=10\n"
    "                    data=04040204018000000000000000000000\n"
    "    SEQUENCE: length=10\n"
    "        OID: 1.2.840.113741.1.13.1.3\n"
    "        OCTET_STRING:\n"
    "            length=2\n"
    "            data=0000\n"
    "    SEQUENCE: length=14\n"
    "        OID: 1.2.840.113741.1.13.1.4\n"
    "        OCTET_STRING:\n"
    "            length=6\n"
    "            data=00906ea10000\n"
    "    SEQUENCE: length=f\n"
    "        OID: 1.2.840.113741.1.13.1.5\n"
    "        UNKNOWN:\n"
    "            tag=0a\n"
    "            length=1\n"
    "            data=00\n";

static void _parse_asn1(oe_asn1_t* asn1, char** str, size_t depth)
{
    oe_result_t r;

    while (oe_asn1_offset(asn1) < asn1->length)
    {
        uint8_t tag;
        r = oe_asn1_peek_tag(asn1, &tag);
        OE_TEST(r == OE_OK);

        switch (tag)
        {
            case OE_ASN1_TAG_CONSTRUCTED | OE_ASN1_TAG_SEQUENCE:
            {
                oe_asn1_t sequence;
                r = oe_asn1_get_sequence(asn1, &sequence);
                OE_TEST(r == OE_OK);
                size_t length = sequence.length;

                _indent(str, depth);
                _printf(str, "SEQUENCE: length=%zx\n", length);

                _parse_asn1(&sequence, str, depth + 1);
                break;
            }
            case OE_ASN1_TAG_INTEGER:
            {
                int value;
                r = oe_asn1_get_integer(asn1, &value);
                OE_TEST(r == OE_OK);

                _indent(str, depth);
                _printf(str, "INTEGER: value=%d\n", value);
                break;
            }
            case OE_ASN1_TAG_OID:
            {
                oe_oid_string_t oid;
                r = oe_asn1_get_oid(asn1, &oid);
                OE_TEST(r == OE_OK);

                _indent(str, depth);
                _printf(str, "OID: %s\n", oid.buf);
                break;
            }
            case OE_ASN1_TAG_OCTET_STRING:
            {
                const uint8_t* data;
                size_t length;
                r = oe_asn1_get_octet_string(asn1, &data, &length);
                OE_TEST(r == OE_OK);

                _indent(str, depth);
                _printf(str, "OCTET_STRING:\n");
                _indent(str, depth + 1);
                _printf(str, "length=%zx\n", length);
                _indent(str, depth + 1);
                _printf(str, "data=");
                _hex_dump(str, data, length);
                _printf(str, "\n");
                break;
            }
            default:
            {
                uint8_t tag;
                size_t length;
                const uint8_t* data;

                r = oe_asn1_get(asn1, &tag, &data, &length);
                OE_TEST(r == OE_OK);

                _indent(str, depth);
                _printf(str, "UNKNOWN:\n");
                _indent(str, depth + 1);
                _printf(str, "tag=%02x\n", tag);
                _indent(str, depth + 1);
                _printf(str, "length=%zu\n", length);
                _indent(str, depth + 1);
                _printf(str, "data=");
                _hex_dump(str, data, length);
                _printf(str, "\n");

                break;
            }
        }
    }

    OE_TEST(oe_asn1_offset(asn1) == asn1->length);
}

static void _test_asn1_parsing(void)
{
    oe_cert_t cert;
    uint8_t data[4096];
    size_t size = sizeof(data);
    const char OID[] = "1.2.840.113741.1.13.1";
    oe_result_t r;

    printf("=== begin %s()\n", __FUNCTION__);

    OE_TEST(oe_cert_read_pem(_CERT, sizeof(_CERT), &cert) == OE_OK);

    /* Find the SGX_EXTENSION */
    r = oe_cert_find_extension(&cert, OID, data, &size);
    OE_TEST(r == OE_OK);

    oe_hex_dump(data, size);

    oe_cert_free(&cert);

    oe_asn1_t asn1;
    r = oe_asn1_init(&asn1, data, size);
    OE_TEST(r == OE_OK);
    OE_TEST(asn1.data == data);
    OE_TEST(asn1.length == size);

    char* str = NULL;
    _parse_asn1(&asn1, &str, 0);

    printf("str=%s\n", str);

    OE_TEST(str != NULL);
    OE_TEST(strcmp(str, _PARSE_OUTPUT) == 0);

    free(str);

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestASN1(void)
{
    _test_asn1_parsing();
}
