// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec.h"
#include "ec_tests.h"
#include "hash.h"

/* Certificate with an EC key */
static const char _CERT[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDRDCCAuqgAwIBAgIVAO34O//eez2nCYF6dX5lnmDXUhoHMAoGCCqGSM49BAMC\n"
    "MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK\n"
    "DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\n"
    "BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xODAyMjcxNDI5MTBaFw0yNTAyMjcxNDI5\n"
    "MTBaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV\n"
    "BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG\n"
    "A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
    "ebMENxGyc7Ns/OV4bt6OOZy9KxUzFtPOwuGq9chDuJkgz1M/4iLtm0STR8mIENnJ\n"
    "vwS0E6STuxsCtNGIzNscOKOCAV4wggFaMB8GA1UdIwQYMBaAFJ8Gl+9TIUTU+kx+\n"
    "6LqNs9Ml5JKQMFgGA1UdHwRRME8wTaBLoEmGR2h0dHBzOi8vY2VydGlmaWNhdGVz\n"
    "LnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vSW50ZWxTR1hQQ0tQcm9jZXNzb3Iu\n"
    "Y3JsMB0GA1UdDgQWBBQUdCfHZzHpiEurA+45dylYXpVvDjAOBgNVHQ8BAf8EBAMC\n"
    "BsAwDAYDVR0TAQH/BAIwADCBnwYJKoZIhvhNAQ0BAQH/BIGOMIGLMB4GCiqGSIb4\n"
    "TQENAQEEEAusByQ8F/2YbRVLVQlDPxUwHgYKKoZIhvhNAQ0BAgQQAAAAAAEBAAAA\n"
    "AAAAAAAAADAQBgoqhkiG+E0BDQEDBAIAADAQBgoqhkiG+E0BDQEEBAIAADAUBgoq\n"
    "hkiG+E0BDQEFBAYgkG6hAAAwDwYKKoZIhvhNAQ0BBgoBADAKBggqhkjOPQQDAgNI\n"
    "ADBFAiEAhY2Bdn5aQJH2Fj1YZriJ7DpmQCbqRyVxU65bd8v0O/4CIA2IWOarGysj\n"
    "RvR+bMRtTbhiRXkV9JD2FJA24tP32pw+\n"
    "-----END CERTIFICATE-----\n";

/* A certficiate without any extensions */
static const char _CERT_WITHOUT_EXTENSIONS[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDMzCCAhsCAhABMA0GCSqGSIb3DQEBCwUAMGMxGjAYBgNVBAMMEVRlc3QgSW50\n"
    "ZXJtZWRpYXRlMQ4wDAYDVQQIDAVUZXhhczELMAkGA1UEBhMCVVMxEjAQBgNVBAoM\n"
    "CU1pY3Jvc29mdDEUMBIGA1UECwwLT3BlbkVuY2xhdmUwHhcNMTgwMjEzMTc1MjUz\n"
    "WhcNMTkwMjEzMTc1MjUzWjBbMRIwEAYDVQQDDAlUZXN0IExlYWYxDjAMBgNVBAgM\n"
    "BVRleGFzMQswCQYDVQQGEwJVUzESMBAGA1UECgwJTWljcm9zb2Z0MRQwEgYDVQQL\n"
    "DAtPcGVuRW5jbGF2ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOjL\n"
    "A0tUP/Sw+L9KowKL94PJe2Bk9u0YeeRa0z1PyIoLVE3KCeOLQueo7gQwah0s/ZA1\n"
    "53lggkyt3VjMOUC5FBS5hy79VcoInrrS9DG8PtZBk3AobDcUBNipWIJ5lofijppi\n"
    "uRFfr4HtMN9TYJhfWnau7puep5X/HeW0k3/Hox8+R6Gdu74QkTILVrDh6EcXzLUv\n"
    "XXFu0bi/pDhoBeW+HGxK8ot+wjKt/NjnYc3KlrNQVDzBDEpXx5enWFbow37O6Rab\n"
    "+iHCkvOYvJe1tgJTpI65Qi688Xc3/NFzZ3lA3PET+xKjjzBS1wHrumCu9L3ugJJ3\n"
    "ZVHwHlDQ9u9qTRHlGYcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAlP9O97ydoazt\n"
    "w4oGluwo3Wef9O2Nx6OhNqY+lrCx/KkdBHVqGLaveo6UDlkRQLydyx55ekrMdatG\n"
    "UyzFm6JTAh29R7ocTWdERmNLQNR1yQFCr0JJ1yPHucikY7ubD0iIxlAliPKPsH/S\n"
    "t4pff8GRRrv5+jCON6zT2lX+ZVOCwyolu5oZWFI6iWy6JldYdaHhmiy3gP/F2abr\n"
    "NASwM79RRO+JGskwgswboXp8Tg83jzdbSe6DL6LfK0UgpeEr3QtNhDMkw7KY1oXs\n"
    "7WxpjlnJCyCkAW0c5+Hh2WgZLwYXcfRXer6WuugAz6WPayLDsHf0ZqiuiVjkbS1l\n"
    "ln6O0i8HeQ==\n"
    "-----END CERTIFICATE-----\n";

/* Certificate chain organized from leaf-to-root */
static const char _CHAIN[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEeTCCBB+gAwIBAgIUCLZOGlkHY7MDrT4wyodHxMlDpSowCgYIKoZIzj0EAwIw\n"
    "cTEjMCEGA1UEAwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoM\n"
    "EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE\n"
    "CAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE4MDUzMDExMzMwNVoXDTI1MDUzMDExMzMw\n"
    "NVowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE\n"
    "CgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD\n"
    "VQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATW\n"
    "xmGk363GUJ+JrxRwGC9lRLyIarJntKUP5lqgQjFSj6u+zK8w+JXLhSmOctWqG29T\n"
    "3eItOqjX9zeLbIJ1bhbwo4IClDCCApAwHwYDVR0jBBgwFoAU5btSj4D54zOuGaz6\n"
    "Y0Z4EfNhu6QwWAYDVR0fBFEwTzBNoEugSYZHaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMu\n"
    "dHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFBDS1Byb2Nlc3Nvci5j\n"
    "cmwwHQYDVR0OBBYEFKGnZhYL+u0LdXb3Q4gVmfhWgirlMA4GA1UdDwEB/wQEAwIG\n"
    "wDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhNAQ0BBIIBxTCCAcEwHgYKKoZIhvhN\n"
    "AQ0BAQQQoOhb4fIWDhGRy2yRyuyGgzCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqG\n"
    "SIb4TQENAQIBAgEEMBAGCyqGSIb4TQENAQICAgEEMBAGCyqGSIb4TQENAQIDAgEC\n"
    "MBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4TQENAQIFAgEBMBEGCyqGSIb4TQEN\n"
    "AQIGAgIAgDAQBgsqhkiG+E0BDQECBwIBADAQBgsqhkiG+E0BDQECCAIBADAQBgsq\n"
    "hkiG+E0BDQECCQIBADAQBgsqhkiG+E0BDQECCgIBADAQBgsqhkiG+E0BDQECCwIB\n"
    "ADAQBgsqhkiG+E0BDQECDAIBADAQBgsqhkiG+E0BDQECDQIBADAQBgsqhkiG+E0B\n"
    "DQECDgIBADAQBgsqhkiG+E0BDQECDwIBADAQBgsqhkiG+E0BDQECEAIBADAQBgsq\n"
    "hkiG+E0BDQECEQIBBTAfBgsqhkiG+E0BDQECEgQQBAQCBAGAAAAAAAAAAAAAADAQ\n"
    "BgoqhkiG+E0BDQEDBAIAADAUBgoqhkiG+E0BDQEEBAYAkG6hAAAwDwYKKoZIhvhN\n"
    "AQ0BBQoBADAKBggqhkjOPQQDAgNIADBFAiEA9im3EzMQDdJrWbQoML/pTFuhjUuk\n"
    "8yainoRd1tJ/tgUCIGgo6SHqeEw0h2lRw4sZGWjEHLosoPIme3t+Gw9QosI5\n"
    "-----END CERTIFICATE-----\n"
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

/* X-coordinate of key contained in _CERT */
static const uint8_t _CERT_KEY_X[] = {
    0x79, 0xB3, 0x04, 0x37, 0x11, 0xB2, 0x73, 0xB3, 0x6C, 0xFC, 0xE5,
    0x78, 0x6E, 0xDE, 0x8E, 0x39, 0x9C, 0xBD, 0x2B, 0x15, 0x33, 0x16,
    0xD3, 0xCE, 0xC2, 0xE1, 0xAA, 0xF5, 0xC8, 0x43, 0xB8, 0x99,
};

/* Y-coordinate of key contained in _CERT */
static const uint8_t _CERT_KEY_Y[] = {
    0x20, 0xCF, 0x53, 0x3F, 0xE2, 0x22, 0xED, 0x9B, 0x44, 0x93, 0x47,
    0xC9, 0x88, 0x10, 0xD9, 0xC9, 0xBF, 0x04, 0xB4, 0x13, 0xA4, 0x93,
    0xBB, 0x1B, 0x02, 0xB4, 0xD1, 0x88, 0xCC, 0xDB, 0x1C, 0x38,
};

static const char _PRIVATE_KEY[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHQCAQEEIKVVUe1F/MxIp6jmrZ24/8iI6WTj1QDamxZLHQ8ZbL4woAcGBSuBBAAK\n"
    "oUQDQgAEmAxYbaM1rpk+d1KX5pHn0GuuaL5wgEA8xoLzHqVcX1dCOyN1rnZP9axj\n"
    "h8t36IjqPhnxNvCPruzBq/KRbbpIZA==\n"
    "-----END EC PRIVATE KEY-----\n";

static const char _PUBLIC_KEY[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEmAxYbaM1rpk+d1KX5pHn0GuuaL5wgEA8\n"
    "xoLzHqVcX1dCOyN1rnZP9axjh8t36IjqPhnxNvCPruzBq/KRbbpIZA==\n"
    "-----END PUBLIC KEY-----\n";

static const uint8_t _SIGNATURE[] = {
    0x30, 0x45, 0x02, 0x21, 0x00, 0x89, 0x3a, 0xf7, 0xe5, 0xf2, 0x21, 0xe1,
    0xf9, 0xdc, 0xe0, 0x92, 0x82, 0xe6, 0xe4, 0xec, 0xcc, 0x68, 0x6d, 0x00,
    0x5d, 0x0e, 0x9c, 0xd5, 0x08, 0x48, 0x8b, 0x09, 0x5f, 0x20, 0xee, 0xbe,
    0x95, 0x02, 0x20, 0x6e, 0xaa, 0xd2, 0x15, 0xf9, 0xf3, 0xaa, 0xc2, 0x19,
    0xc5, 0x4c, 0x44, 0x0b, 0xa7, 0x2c, 0x3e, 0xe9, 0xc3, 0xb6, 0xf3, 0xb4,
    0x04, 0x51, 0xc6, 0xe9, 0xf1, 0x69, 0x46, 0xb0, 0x3e, 0x22, 0xe6,
};

static size_t _SIGNATURE_SIZE = sizeof(_SIGNATURE);

// Test EC signing operation over an ASCII alphabet string. Note that two
// signatures over the same data produce different hex sequences, although
// signature verification will still succeed.
static void _TestSignAndVerify()
{
    printf("=== begin %s()\n", __FUNCTION__);

    uint8_t* signature = NULL;
    size_t signatureSize = 0;
    oe_result_t r;

    {
        oe_ec_private_key_t key = {0};

        r = oe_ec_private_key_read_pem(
            (const uint8_t*)_PRIVATE_KEY, sizeof(_PRIVATE_KEY), &key);
        OE_TEST(r == OE_OK);

        r = oe_ec_private_key_sign(
            &key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            &signatureSize);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(signature = (uint8_t*)malloc(signatureSize));

        r = oe_ec_private_key_sign(
            &key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            &signatureSize);
        OE_TEST(r == OE_OK);

        OE_TEST(signature != NULL);
        OE_TEST(signatureSize != 0);

        oe_ec_private_key_free(&key);
    }

    {
        oe_ec_public_key_t key = {0};

        r = oe_ec_public_key_read_pem(
            (const uint8_t*)_PUBLIC_KEY, sizeof(_PUBLIC_KEY), &key);
        OE_TEST(r == OE_OK);

        r = oe_ec_public_key_verify(
            &key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            signatureSize);
        OE_TEST(r == OE_OK);

        r = oe_ec_public_key_verify(
            &key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            _SIGNATURE,
            _SIGNATURE_SIZE);
        OE_TEST(r == OE_OK);

        oe_ec_public_key_free(&key);
    }

    /* Convert signature to raw form and then back to ASN.1 */
    {
        uint8_t rData[1024];
        size_t rSize = sizeof(rData);
        uint8_t sData[1024];
        size_t sSize = sizeof(sData);

        r = oe_ecdsa_signature_read_der(
            signature, signatureSize, rData, &rSize, sData, &sSize);
        OE_TEST(r == OE_OK);
        OE_TEST(rSize == 32);
        OE_TEST(sSize == 32);

        uint8_t data[signatureSize];
        size_t size = sizeof(data);
        r = oe_ecdsa_signature_write_der(
            data, &size, rData, rSize, sData, sSize);
        OE_TEST(r == OE_OK);
        OE_TEST(signatureSize == size);
        OE_TEST(memcmp(signature, data, signatureSize) == 0);
    }

    /* Convert a known signature to raw form and back */
    {
        const uint8_t SIG[] = {
            0x30, 0x45, 0x02, 0x20, 0x6A, 0xCD, 0x74, 0xB9, 0x8B, 0x1A, 0xDD,
            0xA3, 0x3D, 0x84, 0x42, 0x44, 0x1F, 0x9B, 0x62, 0x5E, 0x9E, 0xB7,
            0x3F, 0x3C, 0x89, 0xFD, 0xFA, 0xFE, 0x2B, 0x25, 0x7C, 0x43, 0x29,
            0xE3, 0x3D, 0x43, 0x02, 0x21, 0x00, 0xDE, 0xEB, 0x54, 0xF8, 0x6C,
            0x7D, 0xCD, 0xA2, 0x0D, 0x8B, 0x10, 0xCB, 0x4D, 0x7D, 0x8B, 0x14,
            0xDC, 0x54, 0x83, 0x87, 0xD3, 0x35, 0x5A, 0x48, 0xD1, 0x67, 0xD1,
            0xF0, 0xA8, 0x4B, 0x31, 0xBE,
        };
        const uint8_t R[] = {
            0x6A, 0xCD, 0x74, 0xB9, 0x8B, 0x1A, 0xDD, 0xA3, 0x3D, 0x84, 0x42,
            0x44, 0x1F, 0x9B, 0x62, 0x5E, 0x9E, 0xB7, 0x3F, 0x3C, 0x89, 0xFD,
            0xFA, 0xFE, 0x2B, 0x25, 0x7C, 0x43, 0x29, 0xE3, 0x3D, 0x43,
        };

        const uint8_t S[] = {
            0xDE, 0xEB, 0x54, 0xF8, 0x6C, 0x7D, 0xCD, 0xA2, 0x0D, 0x8B, 0x10,
            0xCB, 0x4D, 0x7D, 0x8B, 0x14, 0xDC, 0x54, 0x83, 0x87, 0xD3, 0x35,
            0x5A, 0x48, 0xD1, 0x67, 0xD1, 0xF0, 0xA8, 0x4B, 0x31, 0xBE,

        };
        uint8_t rData[1024];
        size_t rSize = sizeof(rData);
        uint8_t sData[1024];
        size_t sSize = sizeof(sData);

        r = oe_ecdsa_signature_read_der(
            SIG, sizeof(SIG), rData, &rSize, sData, &sSize);
        OE_TEST(r == OE_OK);
        OE_TEST(rSize == sizeof(R));
        OE_TEST(sSize == sizeof(S));
        OE_TEST(memcmp(rData, R, rSize) == 0);
        OE_TEST(memcmp(sData, S, sSize) == 0);

        uint8_t data[sizeof(SIG)];
        size_t size = sizeof(data);
        r = oe_ecdsa_signature_write_der(
            data, &size, rData, rSize, sData, sSize);
        OE_TEST(r == OE_OK);
        OE_TEST(sizeof(SIG) == size);
        OE_TEST(memcmp(SIG, data, sizeof(SIG)) == 0);
    }

    free(signature);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _TestGenerate()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_private_key_t privateKey = {0};
    oe_ec_public_key_t publicKey = {0};
    uint8_t* signature = NULL;
    size_t signatureSize = 0;

    r = oe_ec_generate_key_pair(OE_EC_TYPE_SECP256R1, &privateKey, &publicKey);
    OE_TEST(r == OE_OK);

    r = oe_ec_private_key_sign(
        &privateKey,
        OE_HASH_TYPE_SHA256,
        &ALPHABET_HASH,
        sizeof(ALPHABET_HASH),
        signature,
        &signatureSize);
    OE_TEST(r == OE_BUFFER_TOO_SMALL);

    OE_TEST(signature = (uint8_t*)malloc(signatureSize));

    r = oe_ec_private_key_sign(
        &privateKey,
        OE_HASH_TYPE_SHA256,
        &ALPHABET_HASH,
        sizeof(ALPHABET_HASH),
        signature,
        &signatureSize);
    OE_TEST(r == OE_OK);

    r = oe_ec_public_key_verify(
        &publicKey,
        OE_HASH_TYPE_SHA256,
        &ALPHABET_HASH,
        sizeof(ALPHABET_HASH),
        signature,
        signatureSize);
    OE_TEST(r == OE_OK);

    free(signature);
    oe_ec_private_key_free(&privateKey);
    oe_ec_public_key_free(&publicKey);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _TestWritePrivate()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_public_key_t publicKey = {0};
    oe_ec_private_key_t key1 = {0};
    oe_ec_private_key_t key2 = {0};
    uint8_t* pemData1 = NULL;
    size_t pemSize1 = 0;
    uint8_t* pemData2 = NULL;
    size_t pemSize2 = 0;

    r = oe_ec_generate_key_pair(OE_EC_TYPE_SECP256R1, &key1, &publicKey);
    OE_TEST(r == OE_OK);

    {
        r = oe_ec_private_key_write_pem(&key1, pemData1, &pemSize1);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(pemData1 = (uint8_t*)malloc(pemSize1));

        r = oe_ec_private_key_write_pem(&key1, pemData1, &pemSize1);
        OE_TEST(r == OE_OK);
    }

    OE_TEST(pemSize1 != 0);
    OE_TEST(pemData1[pemSize1 - 1] == '\0');
    OE_TEST(strlen((char*)pemData1) == pemSize1 - 1);

    r = oe_ec_private_key_read_pem(pemData1, pemSize1, &key2);
    OE_TEST(r == OE_OK);

    {
        r = oe_ec_private_key_write_pem(&key2, pemData2, &pemSize2);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(pemData2 = (uint8_t*)malloc(pemSize2));

        r = oe_ec_private_key_write_pem(&key2, pemData2, &pemSize2);
        OE_TEST(r == OE_OK);
    }

    OE_TEST(pemSize1 == pemSize2);
    OE_TEST(memcmp(pemData1, pemData2, pemSize1) == 0);

    free(pemData1);
    free(pemData2);
    oe_ec_public_key_free(&publicKey);
    oe_ec_private_key_free(&key1);
    oe_ec_private_key_free(&key2);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _TestWritePublic()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_public_key_t key = {0};
    void* pemData = NULL;
    size_t pemSize = 0;

    r = oe_ec_public_key_read_pem(
        (const uint8_t*)_PUBLIC_KEY, sizeof(_PUBLIC_KEY), &key);
    OE_TEST(r == OE_OK);

    {
        r = oe_ec_public_key_write_pem(&key, pemData, &pemSize);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(pemData = (uint8_t*)malloc(pemSize));

        r = oe_ec_public_key_write_pem(&key, pemData, &pemSize);
        OE_TEST(r == OE_OK);
    }

    OE_TEST(sizeof(_PUBLIC_KEY) == pemSize);
    OE_TEST(memcmp(_PUBLIC_KEY, pemData, pemSize) == 0);

    free(pemData);
    oe_ec_public_key_free(&key);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _TestCertMethods()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;

    /* Test oe_cert_get_ec_public_key() */
    {
        oe_cert_t cert = {0};
        oe_ec_public_key_t key = {0};

        r = oe_cert_read_pem(_CERT, sizeof(_CERT), &cert);
        OE_TEST(r == OE_OK);

        r = oe_cert_get_ec_public_key(&cert, &key);
        OE_TEST(r == OE_OK);

        /* Test oe_ec_public_key_to_coordinates() */
        {
            uint8_t* xData = NULL;
            size_t xSize = 0;
            uint8_t* yData = NULL;
            size_t ySize = 0;

            /* Determine the required size of the buffer */
            r = oe_ec_public_key_to_coordinates(
                &key, NULL, &xSize, NULL, &ySize);
            OE_TEST(r == OE_BUFFER_TOO_SMALL);
            OE_TEST(xSize == sizeof(_CERT_KEY_X));
            OE_TEST(ySize == sizeof(_CERT_KEY_Y));

            /* Fetch the key bytes */
            OE_TEST(xData = (uint8_t*)calloc(1, xSize));
            OE_TEST(yData = (uint8_t*)calloc(1, ySize));
            r = oe_ec_public_key_to_coordinates(
                &key, xData, &xSize, yData, &ySize);
            OE_TEST(r == OE_OK);

            /* Does it match expected key? */
            OE_TEST(xSize == sizeof(_CERT_KEY_X));
            OE_TEST(ySize == sizeof(_CERT_KEY_Y));
            OE_TEST(memcmp(_CERT_KEY_X, xData, sizeof(_CERT_KEY_X)) == 0);
            OE_TEST(memcmp(_CERT_KEY_Y, yData, sizeof(_CERT_KEY_Y)) == 0);
            free(xData);
            free(yData);
        }

        /* Test oe_ec_public_key_equal() */
        {
            bool equal;
            OE_TEST(oe_ec_public_key_equal(&key, &key, &equal) == OE_OK);
            OE_TEST(equal == true);
        }

        oe_ec_public_key_free(&key);
        oe_cert_free(&cert);
    }

    /* Test oe_cert_chain_get_cert() */
    {
        oe_cert_chain_t chain;

        /* Load the chain from PEM format */
        r = oe_cert_chain_read_pem(_CHAIN, sizeof(_CHAIN), &chain);
        OE_TEST(r == OE_OK);

        /* Get the length of the chain */
        size_t length;
        r = oe_cert_chain_get_length(&chain, &length);
        OE_TEST(r == OE_OK);
        OE_TEST(length == 3);

        /* Get each certificate in the chain */
        for (size_t i = 0; i < length; i++)
        {
            oe_cert_t cert;
            r = oe_cert_chain_get_cert(&chain, i, &cert);
            OE_TEST(r == OE_OK);
            oe_cert_free(&cert);
        }

        /* Test out of bounds */
        {
            oe_cert_t cert;
            r = oe_cert_chain_get_cert(&chain, length + 1, &cert);
            OE_TEST(r == OE_OUT_OF_BOUNDS);
            oe_cert_free(&cert);
        }

        oe_cert_chain_free(&chain);
    }

    /* Test oe_cert_chain_get_root_cert() and oe_cert_chain_get_leaf_cert() */
    {
        oe_cert_chain_t chain;
        oe_cert_t root;
        oe_cert_t leaf;

        /* Load the chain from PEM format */
        r = oe_cert_chain_read_pem(_CHAIN, sizeof(_CHAIN), &chain);
        OE_TEST(r == OE_OK);

        /* Get the root certificate */
        r = oe_cert_chain_get_root_cert(&chain, &root);
        OE_TEST(r == OE_OK);

        /* Get the leaf certificate */
        r = oe_cert_chain_get_leaf_cert(&chain, &leaf);
        OE_TEST(r == OE_OK);

        /* Check that the keys are identical for top and root certificate */
        {
            oe_ec_public_key_t rootKey;
            oe_ec_public_key_t certKey;

            OE_TEST(oe_cert_get_ec_public_key(&root, &rootKey) == OE_OK);

            oe_ec_public_key_free(&rootKey);
            oe_ec_public_key_free(&certKey);
        }

        /* Check that the keys are not identical for leaf and root */
        {
            oe_ec_public_key_t rootKey;
            oe_ec_public_key_t leafKey;
            bool equal;

            OE_TEST(oe_cert_get_ec_public_key(&root, &rootKey) == OE_OK);
            OE_TEST(oe_cert_get_ec_public_key(&leaf, &leafKey) == OE_OK);

            OE_TEST(
                oe_ec_public_key_equal(&rootKey, &leafKey, &equal) == OE_OK);
            OE_TEST(equal == false);

            oe_ec_public_key_free(&rootKey);
            oe_ec_public_key_free(&leafKey);
        }

        oe_cert_free(&root);
        oe_cert_free(&leaf);
        oe_cert_chain_free(&chain);
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _TestKeyFromBytes()
{
    printf("=== begin %s()()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_type_t ecType = OE_EC_TYPE_SECP256R1;

    /* Create a public EC key and get its bytes */
    {
        oe_ec_private_key_t privateKey = {0};
        oe_ec_public_key_t publicKey = {0};
        r = oe_ec_generate_key_pair(ecType, &privateKey, &publicKey);
        OE_TEST(r == OE_OK);

        uint8_t xData[1024];
        size_t xSize = sizeof(xData);
        uint8_t yData[1024];
        size_t ySize = sizeof(yData);

        r = oe_ec_public_key_to_coordinates(
            &publicKey, xData, &xSize, yData, &ySize);
        OE_TEST(r == OE_OK);

        oe_ec_public_key_t key = {0};
        r = oe_ec_public_key_from_coordinates(
            &key, ecType, xData, xSize, yData, ySize);
        OE_TEST(r == OE_OK);

        oe_ec_private_key_free(&privateKey);
        oe_ec_public_key_free(&publicKey);
        oe_ec_public_key_free(&key);
    }

    /* Test creating an EC key from bytes */
    {
        oe_ec_public_key_t key = {0};
        const uint8_t xBytes[32] = {
            0xB5, 0x5D, 0x06, 0xD6, 0xE5, 0xA2, 0xC7, 0x2D, 0x5D, 0xA0, 0xAE,
            0xD5, 0x83, 0x61, 0x4C, 0x51, 0x60, 0xD6, 0xFE, 0x90, 0x8A, 0xC2,
            0x67, 0xF7, 0x31, 0x56, 0x2A, 0x6B, 0xBC, 0xB0, 0x8D, 0xD0,
        };
        const uint8_t yBytes[32] = {
            0xC6, 0xBD, 0x1F, 0xCB, 0xAF, 0xE1, 0x84, 0xE6, 0x2E, 0x9E, 0xAE,
            0xE0, 0x04, 0x4C, 0xC5, 0x59, 0x44, 0x39, 0x52, 0x62, 0x3B, 0x08,
            0xC5, 0xED, 0xBB, 0xC2, 0xD6, 0x50, 0xE7, 0x7B, 0x38, 0xDA,
        };

        r = oe_ec_public_key_from_coordinates(
            &key, ecType, xBytes, sizeof(xBytes), yBytes, sizeof(yBytes));
        OE_TEST(r == OE_OK);

        uint8_t xData[1024];
        size_t xSize = sizeof(xData);
        uint8_t yData[1024];
        size_t ySize = sizeof(yData);
        r = oe_ec_public_key_to_coordinates(&key, xData, &xSize, yData, &ySize);
        OE_TEST(r == OE_OK);

        OE_TEST(sizeof(xBytes) == xSize);
        OE_TEST(sizeof(yBytes) == ySize);
        OE_TEST(memcmp(xData, xBytes, xSize) == 0);
        OE_TEST(memcmp(yData, yBytes, ySize) == 0);
        oe_ec_public_key_free(&key);
    }

    /* Test generating a key and then re-creating it from its bytes */
    {
        oe_ec_private_key_t privateKey = {0};
        oe_ec_public_key_t publicKey = {0};
        oe_ec_public_key_t publicKey2 = {0};
        uint8_t signature[1024];
        size_t signatureSize = sizeof(signature);

        /* Generate a key pair */
        r = oe_ec_generate_key_pair(ecType, &privateKey, &publicKey);
        OE_TEST(r == OE_OK);

        /* Get the bytes from the public key */
        uint8_t xData[1024];
        size_t xSize = sizeof(xData);
        uint8_t yData[1024];
        size_t ySize = sizeof(yData);
        r = oe_ec_public_key_to_coordinates(
            &publicKey, xData, &xSize, yData, &ySize);
        OE_TEST(r == OE_OK);

        /* Create a second public key from the key bytes */
        r = oe_ec_public_key_from_coordinates(
            &publicKey2, ecType, xData, xSize, yData, ySize);
        OE_TEST(r == OE_OK);

        /* Sign data with private key */
        r = oe_ec_private_key_sign(
            &privateKey,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            &signatureSize);
        OE_TEST(r == OE_OK);

        /* Verify data with key created from bytes of original public key */
        r = oe_ec_public_key_verify(
            &publicKey2,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            signatureSize);
        OE_TEST(r == OE_OK);

        oe_ec_private_key_free(&privateKey);
        oe_ec_public_key_free(&publicKey);
        oe_ec_public_key_free(&publicKey2);
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _TestCertChainRead()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_cert_chain_t chain;

    r = oe_cert_chain_read_pem(_CHAIN, sizeof(_CHAIN), &chain);
    OE_TEST(r == OE_OK);

    oe_cert_chain_free(&chain);

    printf("=== passed %s()\n", __FUNCTION__);
}

/* This utility function generates extension definitions for testing */
oe_result_t DumpExtensions(const char* certData, size_t certSize)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_cert_t cert;
    size_t count;
    uint8_t data[4096];
    size_t size = sizeof(data);

    OE_CHECK(oe_cert_read_pem(certData, certSize, &cert));

    /* Get the number of extensions */
    OE_CHECK(oe_cert_extension_count(&cert, &count));

    /* Find the extension with this OID */
    for (size_t i = 0; i < count; i++)
    {
        OE_OIDString extOid;
        size_t tmpSize = size;
        OE_CHECK(oe_cert_get_extension(&cert, i, &extOid, data, &tmpSize));

        printf("static const uint8_t _extensions_data%zu[] =\n", i);
        printf("{\n");

        for (size_t i = 0; i < tmpSize; i++)
        {
            printf("    0x%02x,\n", data[i]);
        }

        printf("};\n\n");
    }

    printf("static const Extension _extensions[] =\n");
    printf("{\n");

    /* Find the extension with this OID */
    for (size_t i = 0; i < count; i++)
    {
        OE_OIDString extOid;
        size_t tmpSize = size;
        OE_CHECK(oe_cert_get_extension(&cert, i, &extOid, data, &tmpSize));

        printf("    {\n");
        printf("        .oid = \"%s\",\n", extOid.buf);
        printf("        .size = %zu,\n", tmpSize);
        printf("        .data = _extensions_data%zu,\n", i);
        printf("    },\n");
    }

    printf("};\n");

    OE_CHECK(oe_cert_free(&cert));

    result = OE_OK;

done:
    return result;
}

typedef struct _Extension
{
    const char* oid;
    size_t size;
    const uint8_t* data;
} Extension;

static const uint8_t _eccert_extensions_data0[] = {
    0x30, 0x16, 0x80, 0x14, 0x9f, 0x06, 0x97, 0xef, 0x53, 0x21, 0x44, 0xd4,
    0xfa, 0x4c, 0x7e, 0xe8, 0xba, 0x8d, 0xb3, 0xd3, 0x25, 0xe4, 0x92, 0x90,
};

static const uint8_t _eccert_extensions_data1[] = {
    0x30, 0x4f, 0x30, 0x4d, 0xa0, 0x4b, 0xa0, 0x49, 0x86, 0x47, 0x68, 0x74,
    0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
    0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74,
    0x65, 0x64, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x69,
    0x6e, 0x74, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x49, 0x6e, 0x74,
    0x65, 0x6c, 0x53, 0x47, 0x58, 0x50, 0x43, 0x4b, 0x50, 0x72, 0x6f, 0x63,
    0x65, 0x73, 0x73, 0x6f, 0x72, 0x2e, 0x63, 0x72, 0x6c,
};

static const uint8_t _eccert_extensions_data2[] = {
    0x04, 0x14, 0x14, 0x74, 0x27, 0xc7, 0x67, 0x31, 0xe9, 0x88, 0x4b,
    0xab, 0x03, 0xee, 0x39, 0x77, 0x29, 0x58, 0x5e, 0x95, 0x6f, 0x0e,
};

static const uint8_t _eccert_extensions_data3[] = {
    0x03,
    0x02,
    0x06,
    0xc0,
};

static const uint8_t _eccert_extensions_data4[] = {
    0x30,
    0x00,
};

static const uint8_t _eccert_extensions_data5[] = {
    0x30, 0x81, 0x8b, 0x30, 0x1e, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8,
    0x4d, 0x01, 0x0d, 0x01, 0x01, 0x04, 0x10, 0x0b, 0xac, 0x07, 0x24, 0x3c,
    0x17, 0xfd, 0x98, 0x6d, 0x15, 0x4b, 0x55, 0x09, 0x43, 0x3f, 0x15, 0x30,
    0x1e, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01,
    0x02, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x10, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x03, 0x04, 0x02, 0x00,
    0x00, 0x30, 0x10, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01,
    0x0d, 0x01, 0x04, 0x04, 0x02, 0x00, 0x00, 0x30, 0x14, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x05, 0x04, 0x06, 0x20,
    0x90, 0x6e, 0xa1, 0x00, 0x00, 0x30, 0x0f, 0x06, 0x0a, 0x2a, 0x86, 0x48,
    0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x06, 0x0a, 0x01, 0x00,
};

static const Extension _eccert_extensions[] = {
    {
        .oid = "2.5.29.35",
        .size = 24,
        .data = _eccert_extensions_data0,
    },
    {
        .oid = "2.5.29.31",
        .size = 81,
        .data = _eccert_extensions_data1,
    },
    {
        .oid = "2.5.29.14",
        .size = 22,
        .data = _eccert_extensions_data2,
    },
    {
        .oid = "2.5.29.15",
        .size = 4,
        .data = _eccert_extensions_data3,
    },
    {
        .oid = "2.5.29.19",
        .size = 2,
        .data = _eccert_extensions_data4,
    },
    {
        .oid = "1.2.840.113741.1.13.1",
        .size = 142,
        .data = _eccert_extensions_data5,
    },
};

static void _TestCertExtensions(
    const char* certData,
    size_t certSize,
    const Extension* extensions,
    size_t extensionsCount,
    const char* testOid)
{
    oe_cert_t cert;

    printf("=== begin %s()\n", __FUNCTION__);

    OE_TEST(oe_cert_read_pem(certData, certSize, &cert) == OE_OK);

    /* Test getting extensions by index */
    {
        size_t count;

        OE_TEST(oe_cert_extension_count(&cert, &count) == OE_OK);
        OE_TEST(count == extensionsCount);

        for (size_t i = 0; i < extensionsCount; i++)
        {
            const Extension* ext = &extensions[i];
            OE_OIDString oid;
            uint8_t data[4096];
            size_t size = sizeof(data);

            OE_TEST(
                oe_cert_get_extension(&cert, i, &oid, data, &size) == OE_OK);

            OE_TEST(strcmp(oid.buf, ext->oid) == 0);
            OE_TEST(size == ext->size);
            OE_TEST(memcmp(data, ext->data, size) == 0);
        }
    }

    /* Test finding extensions by OID */
    {
        for (size_t i = 0; i < extensionsCount; i++)
        {
            const Extension* ext = &extensions[i];
            const char* oid = ext->oid;
            uint8_t data[4096];
            size_t size = sizeof(data);

            OE_TEST(oe_cert_find_extension(&cert, oid, data, &size) == OE_OK);
            OE_TEST(strcmp(oid, ext->oid) == 0);
            OE_TEST(size == ext->size);
            OE_TEST(memcmp(data, ext->data, size) == 0);
        }
    }

    /* Check for an unknown OID */
    if (!extensions)
    {
        oe_result_t r;
        uint8_t data[4096];
        size_t size = sizeof(data);

        r = oe_cert_find_extension(&cert, "1.2.3.4", data, &size);
        OE_TEST(r == OE_NOT_FOUND);
    }

    /* Find the extension with the given OID and check for OE_NOT_FOUND */
    if (!extensions)
    {
        oe_result_t r;
        uint8_t data[4096];
        size_t size = sizeof(data);

        r = oe_cert_find_extension(&cert, testOid, data, &size);

        if (extensions)
            OE_TEST(r == OE_OK);
        else
            OE_TEST(r == OE_NOT_FOUND);
    }

    /* Test for out of bounds */
    {
        oe_result_t r;
        OE_OIDString oid;
        uint8_t data[4096];
        size_t size = sizeof(data);

        r = oe_cert_get_extension(&cert, extensionsCount, &oid, data, &size);
        OE_TEST(r == OE_OUT_OF_BOUNDS);
    }

    oe_cert_free(&cert);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _TestCertWithExtensions()
{
    /* Test a certificate with extensions */
    _TestCertExtensions(
        _CERT,
        sizeof(_CERT),
        _eccert_extensions,
        OE_COUNTOF(_eccert_extensions),
        "1.2.840.113741.1.13.1");
}

static void _TestCertWithoutExtensions()
{
    /* Test a certificate without extensions */
    _TestCertExtensions(
        _CERT_WITHOUT_EXTENSIONS,
        sizeof(_CERT_WITHOUT_EXTENSIONS),
        NULL,
        0,
        "2.5.29.35");
}

const char _SUBJECT[] =
    "/CN=Intel SGX PCK Certificate/O=Intel Corporation/L=Santa Clara/ST=CA"
    "/C=US";

void _TestCertSubject()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_cert_t cert = { 0 };
    char subject[1024];
    size_t subject_size = sizeof(subject);

    r = oe_cert_read_pem(_CERT, sizeof(_CERT), &cert);
    OE_TEST(r == OE_OK);

    subject_size = 0;
    r = oe_cert_get_subject(&cert, NULL, &subject_size);
    OE_TEST(r == OE_BUFFER_TOO_SMALL);

    OE_TEST(subject_size = sizeof(_SUBJECT));

    subject_size = sizeof(subject);
    r = oe_cert_get_subject(&cert, subject, &subject_size);
    OE_TEST(r == OE_OK);

    printf("subject{%s}\n", subject);
    printf("SUBJECT{%s}\n", _SUBJECT);

    OE_TEST(strcmp(subject, _SUBJECT) == 0);
    OE_TEST(subject_size = sizeof(_SUBJECT));

    oe_cert_free(&cert);

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestEC()
{
    _TestCertWithExtensions();
    _TestCertWithoutExtensions();
    _TestSignAndVerify();
    _TestGenerate();
    _TestWritePrivate();
    _TestWritePublic();
    _TestCertMethods();
    _TestKeyFromBytes();
    _TestCertChainRead();
    _TestCertSubject();
}
