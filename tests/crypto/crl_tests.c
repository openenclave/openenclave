// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/cert.h>
#include <openenclave/internal/crl.h>
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

static const char _CHAIN[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICjTCCAjSgAwIBAgIUVs38UHvRdwK2UoHC07LcgvA5+3owCgYIKoZIzj0EAwIw\n"
    "aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\n"
    "cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\n"
    "BgNVBAYTAlVTMB4XDTE4MDExNzA4Mjk1N1oXDTQ5MTIzMTIyNTk1OVowaDEaMBgG\n"
    "A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\n"
    "aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\n"
    "AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5OrBrf+Fu4b8cZB0kCHhTBAH\n"
    "eo/NX9IWlGVfIRLlNEa+k8v5ahmfFlkBbHPN/EKcX5BW5HDidc9dYG8fRWoStaOB\n"
    "uzCBuDAfBgNVHSMEGDAWgBRWzfxQe9F3ArZSgcLTstyC8Dn7ejBSBgNVHR8ESzBJ\n"
    "MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\n"
    "ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUVs38UHvRdwK2UoHC\n"
    "07LcgvA5+3owDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\n"
    "KoZIzj0EAwIDRwAwRAIgKKPvAj1UGUEbut3KrbrQluyQcYFHRbbz3QbQ0GOYFP4C\n"
    "ID6EV/WlI2c2hLe5DpNpN8ENeuEH/vnDJFsHhhCiyg/R\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIClzCCAj6gAwIBAgIVAJ8Gl+9TIUTU+kx+6LqNs9Ml5JKQMAoGCCqGSM49BAMC\n"
    "MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\n"
    "b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\n"
    "CQYDVQQGEwJVUzAeFw0xODAxMTcwODQ0NDZaFw0zMzAxMTcwODQ0NDZaMHExIzAh\n"
    "BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl\n"
    "bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB\n"
    "MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKJe7F9ArKe+\n"
    "ZlvCtIUNhoyzHnmk5jNIezjLjnyKP4eKarx+Y+gy1ygTKBA9sNLG0uQ8Lfx5o4J3\n"
    "Xor9H7QsLsmjgbswgbgwHwYDVR0jBBgwFoAUVs38UHvRdwK2UoHC07LcgvA5+3ow\n"
    "UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl\n"
    "cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFJ8G\n"
    "l+9TIUTU+kx+6LqNs9Ml5JKQMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n"
    "AQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIBZg1MoAdHgikRgniXmZ9P+TQW72w7Rv\n"
    "UuuaCgFgpDbzAiBva7Ybhr3Orfu8BwvcKXOry8VuiY4YobugMzTwjQFINQ==\n"
    "-----END CERTIFICATE-----\n";

/* Certificate revocation list in DER format */
static const uint8_t _CRL[] = {
    0x30, 0x82, 0x01, 0x2a, 0x30, 0x81, 0xd1, 0x02, 0x01, 0x01, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x71,
    0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1a, 0x49,
    0x6e, 0x74, 0x65, 0x6c, 0x20, 0x53, 0x47, 0x58, 0x20, 0x50, 0x43, 0x4b,
    0x20, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x6f, 0x72, 0x20, 0x43,
    0x41, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x11,
    0x49, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
    0x04, 0x07, 0x0c, 0x0b, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c,
    0x61, 0x72, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08,
    0x0c, 0x02, 0x43, 0x41, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x55, 0x53, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x35, 0x33,
    0x30, 0x31, 0x30, 0x32, 0x33, 0x34, 0x32, 0x5a, 0x17, 0x0d, 0x31, 0x39,
    0x30, 0x35, 0x33, 0x30, 0x31, 0x30, 0x32, 0x33, 0x34, 0x32, 0x5a, 0xa0,
    0x2f, 0x30, 0x2d, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x14, 0x04, 0x03,
    0x02, 0x01, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0xe5, 0xbb, 0x52, 0x8f, 0x80, 0xf9, 0xe3, 0x33,
    0xae, 0x19, 0xac, 0xfa, 0x63, 0x46, 0x78, 0x11, 0xf3, 0x61, 0xbb, 0xa4,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xdb, 0x89, 0x2a, 0x67,
    0x1e, 0x52, 0x28, 0xff, 0xd5, 0x93, 0xb8, 0x75, 0xc1, 0x1a, 0x8f, 0xe2,
    0xeb, 0xf3, 0x9f, 0x66, 0x71, 0x43, 0x31, 0x8c, 0xf8, 0xd7, 0x0d, 0x7b,
    0xa2, 0x20, 0x3d, 0xee, 0x02, 0x20, 0x31, 0x78, 0x22, 0x32, 0x1a, 0xe4,
    0x78, 0x4f, 0x1b, 0x72, 0x80, 0xf6, 0x51, 0x95, 0xa7, 0xe9, 0x5d, 0x09,
    0xad, 0xb6, 0x65, 0xdf, 0x1c, 0x11, 0x0d, 0xa8, 0x0b, 0xd0, 0x1f, 0x92,
    0x44, 0x5a,
};

static void _test_verify(const oe_crl_t* crl)
{
    oe_cert_t cert;
    oe_cert_chain_t chain;
    oe_verify_cert_error_t error = {0};

    OE_TEST(oe_cert_read_pem(&cert, _CERT, sizeof(_CERT)) == OE_OK);
    OE_TEST(oe_cert_chain_read_pem(&chain, _CHAIN, sizeof(_CHAIN)));
    OE_TEST(oe_cert_verify(&cert, &chain, crl, &error));

    oe_cert_free(&cert);
    oe_cert_chain_free(&chain);
}

static void _test_verify_with_crl(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl;

    OE_TEST(oe_crl_read_der(&crl, _CRL, sizeof(_CRL)) == OE_OK);
    _test_verify(&crl);
    OE_TEST(oe_crl_free(&crl) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_verify_without_crl(void)
{
    printf("=== begin %s()\n", __FUNCTION__);
    _test_verify(NULL);
    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_get_dates(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl;

    OE_TEST(oe_crl_read_der(&crl, _CRL, sizeof(_CRL)) == OE_OK);

    oe_date_t last;
    oe_date_t next;
    OE_TEST(oe_crl_get_update_dates(&crl, &last, &next) == OE_OK);

    OE_TEST(last.year == 2018);
    OE_TEST(last.month == 4);
    OE_TEST(last.day == 30);
    OE_TEST(last.hours == 10);
    OE_TEST(last.minutes == 23);
    OE_TEST(last.seconds == 42);

    OE_TEST(next.year == 2019);
    OE_TEST(next.month == 4);
    OE_TEST(next.day == 30);
    OE_TEST(next.hours == 10);
    OE_TEST(next.minutes == 23);
    OE_TEST(next.seconds == 42);

    OE_TEST(oe_crl_free(&crl) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestCRL(void)
{
    _test_verify_with_crl();
    _test_verify_without_crl();
    _test_get_dates();
}
