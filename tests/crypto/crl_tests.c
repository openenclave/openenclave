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
    "MIIEejCCBB+gAwIBAgIUTGfXttY4C5zE0xHxH007UM4Y3kgwCgYIKoZIzj0EAwIw\n"
    "cTEjMCEGA1UEAwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoM\n"
    "EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE\n"
    "CAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE4MDUzMDExMzMwNloXDTI1MDUzMDExMzMw\n"
    "NlowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE\n"
    "CgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD\n"
    "VQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQU\n"
    "3aaljg61+9EgoyaGXwB/ZIpqG13NZ1a22vUai97XhJ8jmUt3s+AFDo6qNOp25gRK\n"
    "Y4IBDTuCa/+/Ig/T9Kxjo4IClDCCApAwHwYDVR0jBBgwFoAU5btSj4D54zOuGaz6\n"
    "Y0Z4EfNhu6QwWAYDVR0fBFEwTzBNoEugSYZHaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMu\n"
    "dHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFBDS1Byb2Nlc3Nvci5j\n"
    "cmwwHQYDVR0OBBYEFM4p6V7/4ZeJ5G1IO7Hy3sY7pOUfMA4GA1UdDwEB/wQEAwIG\n"
    "wDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhNAQ0BBIIBxTCCAcEwHgYKKoZIhvhN\n"
    "AQ0BAQQQaciN4lbIWCU3XnuF4BDJmjCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqG\n"
    "SIb4TQENAQIBAgEEMBAGCyqGSIb4TQENAQICAgEEMBAGCyqGSIb4TQENAQIDAgEC\n"
    "MBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4TQENAQIFAgEBMBEGCyqGSIb4TQEN\n"
    "AQIGAgIAgDAQBgsqhkiG+E0BDQECBwIBADAQBgsqhkiG+E0BDQECCAIBADAQBgsq\n"
    "hkiG+E0BDQECCQIBADAQBgsqhkiG+E0BDQECCgIBADAQBgsqhkiG+E0BDQECCwIB\n"
    "ADAQBgsqhkiG+E0BDQECDAIBADAQBgsqhkiG+E0BDQECDQIBADAQBgsqhkiG+E0B\n"
    "DQECDgIBADAQBgsqhkiG+E0BDQECDwIBADAQBgsqhkiG+E0BDQECEAIBADAQBgsq\n"
    "hkiG+E0BDQECEQIBBTAfBgsqhkiG+E0BDQECEgQQBAQCBAGAAAAAAAAAAAAAADAQ\n"
    "BgoqhkiG+E0BDQEDBAIAADAUBgoqhkiG+E0BDQEEBAYAkG6hAAAwDwYKKoZIhvhN\n"
    "AQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEAotlBtfttGxWyJvPbn0T8AWb+ufVW\n"
    "o3vzHFohuwnCQLsCIQCwpr+07Uc1I7XQx8R3gKfxy+KPxQvacmp/s/0NQjEDMA==\n"
    "-----END CERTIFICATE-----\n";

static const char _CHAIN[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICmDCCAj6gAwIBAgIVAOW7Uo+A+eMzrhms+mNGeBHzYbukMAoGCCqGSM49BAMC\n"
    "MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\n"
    "b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\n"
    "CQYDVQQGEwJVUzAeFw0xODA1MjUxMzQzNDFaFw0zMzA1MjUxMzQzNDFaMHExIzAh\n"
    "BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl\n"
    "bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB\n"
    "MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMB0yW2PyWpf\n"
    "6odNPzGnE503t30mxdRm6zKRy86UoBpGMSHUEat/8/V3bIN+QYR21tpLUtzuTx2m\n"
    "HSLi7MCO6byjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww\n"
    "UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl\n"
    "cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFOW7\n"
    "Uo+A+eMzrhms+mNGeBHzYbukMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n"
    "AQH/AgEAMAoGCCqGSM49BAMCA0gAMEUCIQDkybHzpTP7oBIm3iBwO28eAlsyJuQn\n"
    "ayD1LxMurMKCuQIgQkgfZl8ElCe+H2nzmG/pKlcox3jHyJwj8w8CH9w7pIE=\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\n"
    "aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\n"
    "cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\n"
    "BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG\n"
    "A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\n"
    "aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\n"
    "AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n"
    "1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\n"
    "uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\n"
    "MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\n"
    "ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\n"
    "Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYI\n"
    "KoZIzj0EAwIDSQAwRgIhAIpQ/KlO1XE4hH8cw5Ol/E0yzs8PToJe9Pclt+bhfLUg\n"
    "AiEAss0qf7FlMmAMet+gbpLD97ldYy/wqjjmwN7yHRVr2AM=\n"
    "-----END CERTIFICATE-----\n";

/* Certificate revocation list in DER format */
static const uint8_t _CRL[] = {
0x30,
0x82,
0x01,
0x2a,
0x30,
0x81,
0xd1,
0x02,
0x01,
0x01,
0x30,
0x0a,
0x06,
0x08,
0x2a,
0x86,
0x48,
0xce,
0x3d,
0x04,
0x03,
0x02,
0x30,
0x71,
0x31,
0x23,
0x30,
0x21,
0x06,
0x03,
0x55,
0x04,
0x03,
0x0c,
0x1a,
0x49,
0x6e,
0x74,
0x65,
0x6c,
0x20,
0x53,
0x47,
0x58,
0x20,
0x50,
0x43,
0x4b,
0x20,
0x50,
0x72,
0x6f,
0x63,
0x65,
0x73,
0x73,
0x6f,
0x72,
0x20,
0x43,
0x41,
0x31,
0x1a,
0x30,
0x18,
0x06,
0x03,
0x55,
0x04,
0x0a,
0x0c,
0x11,
0x49,
0x6e,
0x74,
0x65,
0x6c,
0x20,
0x43,
0x6f,
0x72,
0x70,
0x6f,
0x72,
0x61,
0x74,
0x69,
0x6f,
0x6e,
0x31,
0x14,
0x30,
0x12,
0x06,
0x03,
0x55,
0x04,
0x07,
0x0c,
0x0b,
0x53,
0x61,
0x6e,
0x74,
0x61,
0x20,
0x43,
0x6c,
0x61,
0x72,
0x61,
0x31,
0x0b,
0x30,
0x09,
0x06,
0x03,
0x55,
0x04,
0x08,
0x0c,
0x02,
0x43,
0x41,
0x31,
0x0b,
0x30,
0x09,
0x06,
0x03,
0x55,
0x04,
0x06,
0x13,
0x02,
0x55,
0x53,
0x17,
0x0d,
0x31,
0x38,
0x30,
0x35,
0x33,
0x30,
0x31,
0x30,
0x32,
0x33,
0x34,
0x32,
0x5a,
0x17,
0x0d,
0x31,
0x39,
0x30,
0x35,
0x33,
0x30,
0x31,
0x30,
0x32,
0x33,
0x34,
0x32,
0x5a,
0xa0,
0x2f,
0x30,
0x2d,
0x30,
0x0a,
0x06,
0x03,
0x55,
0x1d,
0x14,
0x04,
0x03,
0x02,
0x01,
0x01,
0x30,
0x1f,
0x06,
0x03,
0x55,
0x1d,
0x23,
0x04,
0x18,
0x30,
0x16,
0x80,
0x14,
0xe5,
0xbb,
0x52,
0x8f,
0x80,
0xf9,
0xe3,
0x33,
0xae,
0x19,
0xac,
0xfa,
0x63,
0x46,
0x78,
0x11,
0xf3,
0x61,
0xbb,
0xa4,
0x30,
0x0a,
0x06,
0x08,
0x2a,
0x86,
0x48,
0xce,
0x3d,
0x04,
0x03,
0x02,
0x03,
0x48,
0x00,
0x30,
0x45,
0x02,
0x21,
0x00,
0xdb,
0x89,
0x2a,
0x67,
0x1e,
0x52,
0x28,
0xff,
0xd5,
0x93,
0xb8,
0x75,
0xc1,
0x1a,
0x8f,
0xe2,
0xeb,
0xf3,
0x9f,
0x66,
0x71,
0x43,
0x31,
0x8c,
0xf8,
0xd7,
0x0d,
0x7b,
0xa2,
0x20,
0x3d,
0xee,
0x02,
0x20,
0x31,
0x78,
0x22,
0x32,
0x1a,
0xe4,
0x78,
0x4f,
0x1b,
0x72,
0x80,
0xf6,
0x51,
0x95,
0xa7,
0xe9,
0x5d,
0x09,
0xad,
0xb6,
0x65,
0xdf,
0x1c,
0x11,
0x0d,
0xa8,
0x0b,
0xd0,
0x1f,
0x92,
0x44,
0x5a,
};

static void _test_verify(const oe_crl_t* crl)
{
    oe_cert_t cert;
    oe_cert_chain_t chain;
    oe_verify_cert_error_t error = {0};

    OE_TEST(oe_cert_read_pem(&cert, _CERT, sizeof(_CERT)) == OE_OK);
    OE_TEST(oe_cert_chain_read_pem(&chain, _CHAIN, sizeof(_CHAIN)) == OE_OK);
    OE_TEST(oe_cert_verify(&cert, &chain, crl, &error) == OE_OK);

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

    oe_datetime_t last;
    oe_datetime_t next;
    OE_TEST(oe_crl_get_update_dates(&crl, &last, &next) == OE_OK);

    OE_TEST(last.year == 2018);
    OE_TEST(last.month == 5);
    OE_TEST(last.day == 30);
    OE_TEST(last.hours == 10);
    OE_TEST(last.minutes == 23);
    OE_TEST(last.seconds == 42);

    OE_TEST(next.year == 2019);
    OE_TEST(next.month == 5);
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
