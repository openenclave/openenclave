// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/asn1.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "tests.h"

/* Certificate with an EC key */
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

/* A certificate without any extensions */
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
static void _test_sign_and_verify()
{
    printf("=== begin %s()\n", __FUNCTION__);

    uint8_t* signature = NULL;
    size_t signature_size = 0;
    oe_result_t r;

    {
        oe_ec_private_key_t key = {0};

        r = oe_ec_private_key_read_pem(
            &key, (const uint8_t*)_PRIVATE_KEY, sizeof(_PRIVATE_KEY));
        OE_TEST(r == OE_OK);

        r = oe_ec_private_key_sign(
            &key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            &signature_size);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(signature = (uint8_t*)malloc(signature_size));

        r = oe_ec_private_key_sign(
            &key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            &signature_size);
        OE_TEST(r == OE_OK);

        OE_TEST(signature != NULL);
        OE_TEST(signature_size != 0);

        oe_ec_private_key_free(&key);
    }

    {
        oe_ec_public_key_t key = {0};

        r = oe_ec_public_key_read_pem(
            &key, (const uint8_t*)_PUBLIC_KEY, sizeof(_PUBLIC_KEY));
        OE_TEST(r == OE_OK);

        r = oe_ec_public_key_verify(
            &key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            signature_size);
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
        uint8_t data[sizeof(SIG)];
        size_t size = sizeof(data);
        r = oe_ecdsa_signature_write_der(
            data, &size, R, sizeof(R), S, sizeof(S));
        OE_TEST(r == OE_OK);
        OE_TEST(sizeof(SIG) == size);
        OE_TEST(memcmp(SIG, data, sizeof(SIG)) == 0);
    }

    free(signature);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_generate()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_private_key_t private_key = {0};
    oe_ec_public_key_t public_key = {0};
    uint8_t* signature = NULL;
    size_t signature_size = 0;

    printf("oe_ec_gen_key_pair\n");
    r = oe_ec_generate_key_pair(
        OE_EC_TYPE_SECP256R1, &private_key, &public_key);
    OE_TEST(r == OE_OK);

    r = oe_ec_private_key_sign(
        &private_key,
        OE_HASH_TYPE_SHA256,
        &ALPHABET_HASH,
        sizeof(ALPHABET_HASH),
        signature,
        &signature_size);
    OE_TEST(r == OE_BUFFER_TOO_SMALL);

    printf("oe_ec_malloc\n");
    OE_TEST(signature = (uint8_t*)malloc(signature_size));

    printf("oe_ec_private_key_sign\n");
    r = oe_ec_private_key_sign(
        &private_key,
        OE_HASH_TYPE_SHA256,
        &ALPHABET_HASH,
        sizeof(ALPHABET_HASH),
        signature,
        &signature_size);
    OE_TEST(r == OE_OK);

    printf("oe_ec_verify\n");
    r = oe_ec_public_key_verify(
        &public_key,
        OE_HASH_TYPE_SHA256,
        &ALPHABET_HASH,
        sizeof(ALPHABET_HASH),
        signature,
        signature_size);
    OE_TEST(r == OE_OK);

    printf("freeing\n");
    free(signature);
    oe_ec_private_key_free(&private_key);
    oe_ec_public_key_free(&public_key);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_write_private()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_public_key_t public_key = {0};
    oe_ec_private_key_t key1 = {0};
    oe_ec_private_key_t key2 = {0};
    uint8_t* pem_data1 = NULL;
    size_t pem_size1 = 0;
    uint8_t* pem_data2 = NULL;
    size_t pem_size2 = 0;

    r = oe_ec_generate_key_pair(OE_EC_TYPE_SECP256R1, &key1, &public_key);
    OE_TEST(r == OE_OK);

    {
        r = oe_ec_private_key_write_pem(&key1, pem_data1, &pem_size1);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(pem_data1 = (uint8_t*)malloc(pem_size1));

        r = oe_ec_private_key_write_pem(&key1, pem_data1, &pem_size1);
        OE_TEST(r == OE_OK);
    }

    OE_TEST(pem_size1 != 0);
    OE_TEST(pem_data1[pem_size1 - 1] == '\0');
    OE_TEST(strlen((char*)pem_data1) == pem_size1 - 1);

    r = oe_ec_private_key_read_pem(&key2, pem_data1, pem_size1);
    OE_TEST(r == OE_OK);

    {
        r = oe_ec_private_key_write_pem(&key2, pem_data2, &pem_size2);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(pem_data2 = (uint8_t*)malloc(pem_size2));

        r = oe_ec_private_key_write_pem(&key2, pem_data2, &pem_size2);
        OE_TEST(r == OE_OK);
    }

    OE_TEST(pem_size1 == pem_size2);
    OE_TEST(memcmp(pem_data1, pem_data2, pem_size1) == 0);

    free(pem_data1);
    free(pem_data2);
    oe_ec_public_key_free(&public_key);
    oe_ec_private_key_free(&key1);
    oe_ec_private_key_free(&key2);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_write_public()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_public_key_t key = {0};
    void* pem_data = NULL;
    size_t pem_size = 0;

    r = oe_ec_public_key_read_pem(
        &key, (const uint8_t*)_PUBLIC_KEY, sizeof(_PUBLIC_KEY));
    OE_TEST(r == OE_OK);

    {
        r = oe_ec_public_key_write_pem(&key, pem_data, &pem_size);
        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        OE_TEST(pem_data = (uint8_t*)malloc(pem_size));

        r = oe_ec_public_key_write_pem(&key, pem_data, &pem_size);
        OE_TEST(r == OE_OK);
    }

    OE_TEST(sizeof(_PUBLIC_KEY) == pem_size);
    OE_TEST(memcmp(_PUBLIC_KEY, pem_data, pem_size) == 0);

    free(pem_data);
    oe_ec_public_key_free(&key);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_cert_methods()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;

    /* Test oe_cert_get_ec_public_key() */
    {
        oe_cert_t cert = {0};
        oe_ec_public_key_t key = {0};

        r = oe_cert_read_pem(&cert, _CERT, sizeof(_CERT));
        OE_TEST(r == OE_OK);

        r = oe_cert_get_ec_public_key(&cert, &key);
        OE_TEST(r == OE_OK);

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
        r = oe_cert_chain_read_pem(&chain, _CHAIN, sizeof(_CHAIN));
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
        r = oe_cert_chain_read_pem(&chain, _CHAIN, sizeof(_CHAIN));
        OE_TEST(r == OE_OK);

        /* Get the root certificate */
        r = oe_cert_chain_get_root_cert(&chain, &root);
        OE_TEST(r == OE_OK);

        /* Get the leaf certificate */
        r = oe_cert_chain_get_leaf_cert(&chain, &leaf);
        OE_TEST(r == OE_OK);

        /* Check that the keys are identical for top and root certificate */
        {
            oe_ec_public_key_t root_key;
            oe_ec_public_key_t cert_key;

            OE_TEST(oe_cert_get_ec_public_key(&root, &root_key) == OE_OK);

            oe_ec_public_key_free(&root_key);
            oe_ec_public_key_free(&cert_key);
        }

        /* Check that the keys are not identical for leaf and root */
        {
            oe_ec_public_key_t root_key;
            oe_ec_public_key_t leaf_key;
            bool equal;

            OE_TEST(oe_cert_get_ec_public_key(&root, &root_key) == OE_OK);
            OE_TEST(oe_cert_get_ec_public_key(&leaf, &leaf_key) == OE_OK);

            OE_TEST(
                oe_ec_public_key_equal(&root_key, &leaf_key, &equal) == OE_OK);
            OE_TEST(equal == false);

            oe_ec_public_key_free(&root_key);
            oe_ec_public_key_free(&leaf_key);
        }

        oe_cert_free(&root);
        oe_cert_free(&leaf);
        oe_cert_chain_free(&chain);
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_key_from_bytes()
{
    printf("=== begin %s()()\n", __FUNCTION__);

    oe_result_t r;
    oe_ec_type_t ec_type = OE_EC_TYPE_SECP256R1;

    /* Test generating a key and then re-creating it from its bytes */
    {
        const uint8_t private_key_pem[] = {
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20,
            0x45, 0x43, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20,
            0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A, 0x4D, 0x48,
            0x63, 0x43, 0x41, 0x51, 0x45, 0x45, 0x49, 0x4C, 0x72, 0x33, 0x33,
            0x4A, 0x45, 0x4F, 0x6E, 0x45, 0x33, 0x30, 0x6B, 0x55, 0x4D, 0x7A,
            0x32, 0x55, 0x6E, 0x48, 0x4E, 0x37, 0x4D, 0x75, 0x76, 0x38, 0x53,
            0x36, 0x75, 0x55, 0x58, 0x50, 0x4B, 0x4F, 0x30, 0x75, 0x2F, 0x4E,
            0x6D, 0x4D, 0x75, 0x79, 0x65, 0x2F, 0x6F, 0x41, 0x6F, 0x47, 0x43,
            0x43, 0x71, 0x47, 0x53, 0x4D, 0x34, 0x39, 0x0A, 0x41, 0x77, 0x45,
            0x48, 0x6F, 0x55, 0x51, 0x44, 0x51, 0x67, 0x41, 0x45, 0x75, 0x62,
            0x52, 0x48, 0x70, 0x32, 0x44, 0x4C, 0x59, 0x46, 0x58, 0x57, 0x66,
            0x42, 0x31, 0x45, 0x46, 0x62, 0x69, 0x45, 0x52, 0x66, 0x4D, 0x41,
            0x61, 0x56, 0x46, 0x7A, 0x75, 0x6B, 0x54, 0x59, 0x6C, 0x5A, 0x2B,
            0x43, 0x44, 0x55, 0x74, 0x4A, 0x56, 0x6C, 0x6E, 0x33, 0x44, 0x63,
            0x69, 0x6B, 0x35, 0x2F, 0x59, 0x7A, 0x0A, 0x59, 0x44, 0x77, 0x68,
            0x56, 0x37, 0x30, 0x55, 0x68, 0x6F, 0x57, 0x6F, 0x59, 0x62, 0x7A,
            0x38, 0x37, 0x36, 0x4D, 0x77, 0x4C, 0x5A, 0x7A, 0x4F, 0x43, 0x6F,
            0x71, 0x5A, 0x4F, 0x56, 0x49, 0x57, 0x42, 0x41, 0x3D, 0x3D, 0x0A,
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x45, 0x43,
            0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4B, 0x45,
            0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A, 0x00,
        };
        const uint8_t public_key_pem[] = {
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20,
            0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x2D,
            0x2D, 0x2D, 0x2D, 0x2D, 0x0A, 0x4D, 0x46, 0x6B, 0x77, 0x45, 0x77,
            0x59, 0x48, 0x4B, 0x6F, 0x5A, 0x49, 0x7A, 0x6A, 0x30, 0x43, 0x41,
            0x51, 0x59, 0x49, 0x4B, 0x6F, 0x5A, 0x49, 0x7A, 0x6A, 0x30, 0x44,
            0x41, 0x51, 0x63, 0x44, 0x51, 0x67, 0x41, 0x45, 0x75, 0x62, 0x52,
            0x48, 0x70, 0x32, 0x44, 0x4C, 0x59, 0x46, 0x58, 0x57, 0x66, 0x42,
            0x31, 0x45, 0x46, 0x62, 0x69, 0x45, 0x52, 0x66, 0x4D, 0x41, 0x61,
            0x56, 0x46, 0x7A, 0x0A, 0x75, 0x6B, 0x54, 0x59, 0x6C, 0x5A, 0x2B,
            0x43, 0x44, 0x55, 0x74, 0x4A, 0x56, 0x6C, 0x6E, 0x33, 0x44, 0x63,
            0x69, 0x6B, 0x35, 0x2F, 0x59, 0x7A, 0x59, 0x44, 0x77, 0x68, 0x56,
            0x37, 0x30, 0x55, 0x68, 0x6F, 0x57, 0x6F, 0x59, 0x62, 0x7A, 0x38,
            0x37, 0x36, 0x4D, 0x77, 0x4C, 0x5A, 0x7A, 0x4F, 0x43, 0x6F, 0x71,
            0x5A, 0x4F, 0x56, 0x49, 0x57, 0x42, 0x41, 0x3D, 0x3D, 0x0A, 0x2D,
            0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x50, 0x55, 0x42,
            0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D,
            0x2D, 0x0A, 0x00,
        };
        const uint8_t x_data[] = {
            0xB9, 0xB4, 0x47, 0xA7, 0x60, 0xCB, 0x60, 0x55, 0xD6, 0x7C, 0x1D,
            0x44, 0x15, 0xB8, 0x84, 0x45, 0xF3, 0x00, 0x69, 0x51, 0x73, 0xBA,
            0x44, 0xD8, 0x95, 0x9F, 0x82, 0x0D, 0x4B, 0x49, 0x56, 0x59,
        };
        const size_t x_size = sizeof(x_data);

        const uint8_t y_data[] = {
            0xF7, 0x0D, 0xC8, 0xA4, 0xE7, 0xF6, 0x33, 0x60, 0x3C, 0x21, 0x57,
            0xBD, 0x14, 0x86, 0x85, 0xA8, 0x61, 0xBC, 0xFC, 0xEF, 0xA3, 0x30,
            0x2D, 0x9C, 0xCE, 0x0A, 0x8A, 0x99, 0x39, 0x52, 0x16, 0x04,
        };
        const size_t y_size = sizeof(y_data);

        oe_ec_private_key_t private_key = {0};
        oe_ec_public_key_t public_key = {0};
        oe_ec_public_key_t public_key2 = {0};
        uint8_t signature[1024];
        size_t signature_size = sizeof(signature);

        /* Load private key */
        r = oe_ec_private_key_read_pem(
            &private_key, private_key_pem, sizeof(private_key_pem));
        OE_TEST(r == OE_OK);

        /* Load public key */
        r = oe_ec_public_key_read_pem(
            &public_key, public_key_pem, sizeof(public_key_pem));
        OE_TEST(r == OE_OK);

        /* Create a second public key from the key bytes */
        r = oe_ec_public_key_from_coordinates(
            &public_key2, ec_type, x_data, x_size, y_data, y_size);
        OE_TEST(r == OE_OK);

        /* Sign data with private key */
        r = oe_ec_private_key_sign(
            &private_key,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            &signature_size);
        OE_TEST(r == OE_OK);

        /* Verify data with key created from bytes of original public key */
        r = oe_ec_public_key_verify(
            &public_key2,
            OE_HASH_TYPE_SHA256,
            &ALPHABET_HASH,
            sizeof(ALPHABET_HASH),
            signature,
            signature_size);
        OE_TEST(r == OE_OK);

        oe_ec_private_key_free(&private_key);
        oe_ec_public_key_free(&public_key);
        oe_ec_public_key_free(&public_key2);
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_cert_chain_read()
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_result_t r;
    oe_cert_chain_t chain;

    r = oe_cert_chain_read_pem(&chain, _CHAIN, sizeof(_CHAIN));
    OE_TEST(r == OE_OK);

    oe_cert_chain_free(&chain);

    printf("=== passed %s()\n", __FUNCTION__);
}

typedef struct _extension
{
    const char* oid;
    size_t size;
    const uint8_t* data;
} Extension;

static const uint8_t _eccert_extensions_data0[] = {
    0x30, 0x16, 0x80, 0x14, 0xe5, 0xbb, 0x52, 0x8f, 0x80, 0xf9, 0xe3, 0x33,
    0xae, 0x19, 0xac, 0xfa, 0x63, 0x46, 0x78, 0x11, 0xf3, 0x61, 0xbb, 0xa4,
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
    0x04, 0x14, 0xce, 0x29, 0xe9, 0x5e, 0xff, 0xe1, 0x97, 0x89, 0xe4,
    0x6d, 0x48, 0x3b, 0xb1, 0xf2, 0xde, 0xc6, 0x3b, 0xa4, 0xe5, 0x1f,
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
    0x30, 0x82, 0x01, 0xc1, 0x30, 0x1e, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86,
    0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x01, 0x04, 0x10, 0x69, 0xc8, 0x8d, 0xe2,
    0x56, 0xc8, 0x58, 0x25, 0x37, 0x5e, 0x7b, 0x85, 0xe0, 0x10, 0xc9, 0x9a,
    0x30, 0x82, 0x01, 0x64, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d,
    0x01, 0x0d, 0x01, 0x02, 0x30, 0x82, 0x01, 0x54, 0x30, 0x10, 0x06, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x01, 0x02,
    0x01, 0x04, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d,
    0x01, 0x0d, 0x01, 0x02, 0x02, 0x02, 0x01, 0x04, 0x30, 0x10, 0x06, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x03, 0x02,
    0x01, 0x02, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d,
    0x01, 0x0d, 0x01, 0x02, 0x04, 0x02, 0x01, 0x04, 0x30, 0x10, 0x06, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x05, 0x02,
    0x01, 0x01, 0x30, 0x11, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d,
    0x01, 0x0d, 0x01, 0x02, 0x06, 0x02, 0x02, 0x00, 0x80, 0x30, 0x10, 0x06,
    0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x07,
    0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
    0x4d, 0x01, 0x0d, 0x01, 0x02, 0x08, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06,
    0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x09,
    0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
    0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0a, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06,
    0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0b,
    0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
    0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0c, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06,
    0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0d,
    0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
    0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06,
    0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0f,
    0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
    0x4d, 0x01, 0x0d, 0x01, 0x02, 0x10, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06,
    0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x11,
    0x02, 0x01, 0x05, 0x30, 0x1f, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
    0x4d, 0x01, 0x0d, 0x01, 0x02, 0x12, 0x04, 0x10, 0x04, 0x04, 0x02, 0x04,
    0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x10, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d,
    0x01, 0x03, 0x04, 0x02, 0x00, 0x00, 0x30, 0x14, 0x06, 0x0a, 0x2a, 0x86,
    0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04, 0x04, 0x06, 0x00, 0x90,
    0x6e, 0xa1, 0x00, 0x00, 0x30, 0x0f, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86,
    0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x05, 0x0a, 0x01, 0x00,
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
        .size = 453,
        .data = _eccert_extensions_data5,
    },
};

static void _test_cert_extensions(
    const char* cert_data,
    size_t cert_size,
    const Extension* extensions,
    size_t extensions_count,
    const char* test_oid)
{
    oe_cert_t cert;

    printf("=== begin %s()\n", __FUNCTION__);

    OE_TEST(oe_cert_read_pem(&cert, cert_data, cert_size) == OE_OK);

    /* Test finding extensions by OID */
    {
        for (size_t i = 0; i < extensions_count; i++)
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

        r = oe_cert_find_extension(&cert, test_oid, data, &size);

        if (extensions)
            OE_TEST(r == OE_OK);
        else
            OE_TEST(r == OE_NOT_FOUND);
    }

    oe_cert_free(&cert);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_cert_with_extensions()
{
    /* Test a certificate with extensions */
    _test_cert_extensions(
        _CERT,
        sizeof(_CERT),
        _eccert_extensions,
        OE_COUNTOF(_eccert_extensions),
        "1.2.840.113741.1.13.1");
}

static void _test_cert_without_extensions()
{
    /* Test a certificate without extensions */
    _test_cert_extensions(
        _CERT_WITHOUT_EXTENSIONS,
        sizeof(_CERT_WITHOUT_EXTENSIONS),
        NULL,
        0,
        "2.5.29.35");
}

static const char _SGX_CERT[] =
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

static const char _URL[] =
    "https://certificates.trustedservices.intel.com/IntelSGXPCKProcessor.crl";

static void _test_crl_distribution_points(void)
{
    oe_result_t r;
    oe_cert_t cert;
    const char** urls = NULL;
    size_t num_urls;
    size_t buffer_size = 0;

    printf("=== begin %s()\n", __FUNCTION__);

    r = oe_cert_read_pem(&cert, _SGX_CERT, sizeof(_SGX_CERT));
    OE_TEST(r == OE_OK);

    r = oe_get_crl_distribution_points(
        &cert, &urls, &num_urls, NULL, &buffer_size);
    OE_TEST(r == OE_BUFFER_TOO_SMALL);

    {
        uint8_t* buffer = (uint8_t*)malloc(buffer_size);
        OE_TEST(buffer != NULL);

        r = oe_get_crl_distribution_points(
            &cert, &urls, &num_urls, buffer, &buffer_size);

        OE_TEST(num_urls == 1);
        OE_TEST(urls != NULL);
        OE_TEST(urls[0] != NULL);
        OE_TEST(strcmp(urls[0], _URL) == 0);

        printf("URL{%s}\n", urls[0]);

        OE_TEST(r == OE_OK);
        free(buffer);
	}

    r = oe_cert_free(&cert);
    OE_TEST(r == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestEC()
{
    _test_cert_with_extensions();
    _test_cert_without_extensions();
    _test_crl_distribution_points();
    _test_sign_and_verify();
    _test_generate();
    _test_write_private();
    _test_write_public();
    _test_cert_methods();
    _test_key_from_bytes();
    _test_cert_chain_read();
}
