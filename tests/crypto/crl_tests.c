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

static const char _CERT1[] =
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

static const char _CHAIN1[] =
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
static const uint8_t _CRL1[] = {
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

static const char _CERT2[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDWTCCAkECCQCqT+WV9DM/JzANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJV\n"
    "UzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHUmVkbW9uZDEhMB8GA1UE\n"
    "CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRkwFwYDVQQDDBBpbnRlcm1lZGlh\n"
    "dGVjZXJ0MB4XDTE4MTAwMjIzMzAzMVoXDTI4MDkyOTIzMzAzMVowazELMAkGA1UE\n"
    "BhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1JlZG1vbmQxITAf\n"
    "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJbGVhZmNl\n"
    "cnQyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5MbmBRn0+HiQvsg\n"
    "21AuyQaYAokPwuKcKhGEkyNPZGy16jOj0xQmkrAVGJTBkEdTRHTY4oDPyRzInq5u\n"
    "znso0Mmc5PH1785caHHtF88hNPA7OoOpv8LqrpyHHkxje7f4op8JLRnvFKBEBYdN\n"
    "zBEyx5aXFuUTCXs7UTZT2h3jLesLs0sSUWDZTODWlZrJUO2p1pYZmSxb7n/6EduM\n"
    "5o0KQjpycLcNYVco/+jzMjsWUT+ovKR17SLRMFhbVRbUd/MpNZOYrFrA/OAx8eP9\n"
    "ebb7pc3xolWGd6gOYJACN1jkek9hiV7b2ZLyZNRvpt/KjetRuWWYQp6KzqiVq3/H\n"
    "metAUQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA2p1TidfCltPzDyan0xgaNmR5q\n"
    "ROU0DkgmmffE7vGiLTs5Km1LnHPrbHC+Vd1FN5G/dKwdpJhRyqBabrcjHUPDoq2i\n"
    "IMgkKXbGCAME+p4tzRsThEQ6dToTKRgbUxAxoGwlhxwnLAHiTEu+TChSAmkASpXg\n"
    "i2sOO3NQFRcEFE5X879uSTK57nI3S7QmPJ5z8jPaXFkX4ZaYFkLKbzvUY321PYHi\n"
    "8htvml95++HrakKViDoA0OBhMwQf+C37oDqpTskHk0esLFqYQKoChDB2DjHh8qjq\n"
    "7n9cgRHF5ma+T6R8qbyiWGsv5y1GH7dLcu+i0mwT/nWNqHEGAeMbpgOkhiit\n"
    "-----END CERTIFICATE-----\n";

static const char _CHAIN2[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDWDCCAkACCQDvG3zO9O3U1DANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJV\n"
    "UzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHUmVkbW9uZDEhMB8GA1UE\n"
    "CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMREwDwYDVQQDDAhyb290Y2VydDAe\n"
    "Fw0xODEwMDIyMzI1NDZaFw0yODA5MjkyMzI1NDZaMHIxCzAJBgNVBAYTAlVTMRMw\n"
    "EQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdSZWRtb25kMSEwHwYDVQQKDBhJ\n"
    "bnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxGTAXBgNVBAMMEGludGVybWVkaWF0ZWNl\n"
    "cnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHPkVLAZyftsGOgaZv\n"
    "Fw6zZjPN5LJJITEZLBygwoj+qplKBp8W1U/FKgc4c90EpCu1ytAaxmCXUWMt45z/\n"
    "wZsy7U4dDetJ+DbTzTcATPiD9cHO+dV1ltcJaWPE4hV/FEDSPOjV6h5prAKWTa1t\n"
    "HUJkRZR1kf2GcyHynP/LKTRlCRWu7x+9w51qLoBDw2MlzDLlu5UXK3g5mxFtuCHZ\n"
    "rBZxsEa+4qA44bBwlleDov0qkO/J+U4hsabSoTKMOr4DyBpfaSS9R8tsyIyfaXh8\n"
    "UQJIVrDBFnIB7ND2Jxa7nV49Lth3mApQ1xeAU0jP9u3/g6AVOnCcmehoGKny1jet\n"
    "ok8lAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHkdRgB+kPXxw9TaszBq+OtsOu2y\n"
    "CX9jGh00996rZSP2Cf9sluxD7vzu5SDS/XMhWLbUcMFlzJrztkjRBTiugqGVOJ6T\n"
    "hvJn2Nj+meIVhGCF105T7cdnpFd3dKEXHUIAnP7v4nV0Jl4YzCYwjQpw7rSMl+si\n"
    "QqHnxsTTBOyXnROHXgOM+0VAdK1daWKbCFKMRCNYPG7RM4879I9C4Wc54Fu0n4cW\n"
    "P51cFnNBc5rKX2eVEbNAkpin472rHAQfD3+bKPZMaVO1s3j+UZmo/hgCCxCHtFdo\n"
    "mUTuiMALzrMdFRf7pglwzEYHQT9aNy+f7fPfKC7i4hGtIKKu+TnLIBc22I4=\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDpzCCAo+gAwIBAgIJAMbxuLP/3wKXMA0GCSqGSIb3DQEBCwUAMGoxCzAJBgNV\n"
    "BAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdSZWRtb25kMSEw\n"
    "HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxETAPBgNVBAMMCHJvb3Rj\n"
    "ZXJ0MB4XDTE4MTAwMjIzMjIwMloXDTI4MDkyOTIzMjIwMlowajELMAkGA1UEBhMC\n"
    "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1JlZG1vbmQxITAfBgNV\n"
    "BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDERMA8GA1UEAwwIcm9vdGNlcnQw\n"
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4MwiOHSa8Gf+GMcEZg2gu\n"
    "+J9N7f/tFc1tY+W+DKd3YVrMYftw08Injx7k4xRMwQF2VtthveVkekJ6RXuCv/B3\n"
    "Bhpzx5hJJH8mgrjQqEytcX/ejr/AOPssGk5aYZ1IwCsSGGoj9toCfPCKgIQ5xfgQ\n"
    "AXoYOjVZjuZc4q03zLxlR5elKjiobx4GDwxt1ZvdA6fKAV+rAJYtWSCPr44384Xk\n"
    "5cc01b2xHlsGYM4XlKw4u2uKZLwJZ8P1KznHcXVTryqjPqmmW/tU8a5VRt+jrMdG\n"
    "nAWnUB4RzIQM10Z/w07M7sisTJ5YbE+SYC/F3n5JUWxR8TAr6k6tpw2oLUFcWLuh\n"
    "AgMBAAGjUDBOMB0GA1UdDgQWBBSl9Tnxe6FQeTE1INVs8ApOi1UdLTAfBgNVHSME\n"
    "GDAWgBSl9Tnxe6FQeTE1INVs8ApOi1UdLTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQB6bUbbqC15gWPcP0+6oFeC5NfZ3VnfdVCbjiiGeRhYit7aqUmf\n"
    "EFjxPSeyMpUSmwf1kwPn0wRSBEDaGeTvwXx6w4V/ZB+30u7PxZTTzprLX03vWsT9\n"
    "9PGoS3Ifu2AeLa8pmXZa5Obsbg7JKRXVDj5mO8rkDdLJA9P584PFgWXI2Ud+Vg1d\n"
    "j6dBEi9hGLGFBS2hklQ5jH1PJtW16qkolIr/16ufzMeOTwBmyZ0rIGiRNMtpp4q1\n"
    "Nn+/AiZjyan8PzAKVhViorhNWgfgoS01u3+lqflBQy6jX0dZuhBsbSooSYVy+Rvy\n"
    "xH1K26VvqBkpPmGaWkosYcpln0Ey3vJ1ee+J\n"
    "-----END CERTIFICATE-----\n";

/* This CRL contains _CERT2 */
static const uint8_t _CRL2[] = {
    0x30, 0x82, 0x01, 0xe9, 0x30, 0x81, 0xd2, 0x02, 0x01, 0x01, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
    0x00, 0x30, 0x72, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f,
    0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07,
    0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31, 0x21, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e,
    0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50,
    0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x10, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65,
    0x64, 0x69, 0x61, 0x74, 0x65, 0x63, 0x65, 0x72, 0x74, 0x17, 0x0d, 0x31,
    0x38, 0x31, 0x30, 0x30, 0x33, 0x30, 0x30, 0x30, 0x36, 0x33, 0x37, 0x5a,
    0x17, 0x0d, 0x32, 0x38, 0x30, 0x39, 0x33, 0x30, 0x30, 0x30, 0x30, 0x36,
    0x33, 0x37, 0x5a, 0x30, 0x1c, 0x30, 0x1a, 0x02, 0x09, 0x00, 0xaa, 0x4f,
    0xe5, 0x95, 0xf4, 0x33, 0x3f, 0x27, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x30,
    0x30, 0x33, 0x30, 0x30, 0x30, 0x36, 0x32, 0x32, 0x5a, 0xa0, 0x0e, 0x30,
    0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x14, 0x04, 0x03, 0x02, 0x01,
    0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x6c, 0xb2, 0xd8,
    0x6d, 0x44, 0x7c, 0x5d, 0xdc, 0xd4, 0xb5, 0xb3, 0x5a, 0xdf, 0x59, 0xdf,
    0xc1, 0xac, 0x35, 0x58, 0xdd, 0x74, 0x30, 0xaf, 0xc0, 0x8d, 0x09, 0x9c,
    0xba, 0xfb, 0x8b, 0xf6, 0x95, 0xed, 0x34, 0x81, 0x18, 0x90, 0xb7, 0x01,
    0xf9, 0x01, 0x57, 0x0c, 0xf2, 0xad, 0xb4, 0x40, 0x9e, 0xa2, 0xa2, 0xa0,
    0x59, 0x5c, 0x65, 0x37, 0x76, 0x9f, 0x0c, 0xfc, 0x49, 0x91, 0x45, 0xe2,
    0x72, 0x89, 0xe7, 0x6f, 0xf5, 0x7b, 0x5e, 0x84, 0xad, 0xe0, 0x11, 0x57,
    0xc8, 0xd3, 0x5b, 0xaa, 0x6a, 0x6c, 0x01, 0x66, 0x2f, 0x5a, 0x50, 0xc5,
    0xe2, 0x5b, 0x5e, 0x5e, 0x2e, 0xc1, 0xa9, 0x62, 0x25, 0x23, 0x41, 0xc6,
    0xf1, 0xfb, 0xcf, 0x8a, 0x4a, 0x68, 0x98, 0xa8, 0x34, 0xe1, 0x53, 0x4e,
    0x71, 0xfa, 0x60, 0x35, 0xb7, 0x9d, 0x96, 0x91, 0x84, 0x95, 0x77, 0x17,
    0xaa, 0x53, 0x8c, 0x34, 0xbe, 0x0b, 0x20, 0xde, 0xaa, 0xae, 0xe2, 0x0f,
    0x3a, 0xf7, 0x29, 0xf9, 0xf0, 0x90, 0x70, 0xdf, 0x9e, 0xfe, 0x61, 0x77,
    0xc6, 0x82, 0x65, 0x93, 0x4e, 0xf3, 0x55, 0xa6, 0x5e, 0x55, 0x95, 0xa6,
    0x73, 0xc4, 0x67, 0xdd, 0xa4, 0x15, 0x84, 0xb6, 0x62, 0xa3, 0x5e, 0xa1,
    0x5e, 0xfc, 0xee, 0xa3, 0x62, 0xff, 0x15, 0x33, 0x22, 0xf7, 0xd9, 0xe8,
    0x84, 0xdc, 0xaf, 0x26, 0x32, 0x28, 0x5c, 0x38, 0x1c, 0xb9, 0x4a, 0xdd,
    0x8b, 0x94, 0xa9, 0x0d, 0xac, 0xee, 0xdf, 0xbb, 0x0b, 0xc3, 0x11, 0x0d,
    0xe1, 0x7b, 0x43, 0x82, 0xd7, 0x2e, 0x7f, 0x10, 0x97, 0xa1, 0xcd, 0x72,
    0xe3, 0xc8, 0x43, 0xf1, 0xad, 0xd2, 0x95, 0x4e, 0x70, 0x6a, 0x02, 0xcd,
    0x79, 0x6f, 0x63, 0x2e, 0x29, 0x9e, 0x6a, 0x6a, 0x1c, 0xda, 0x65, 0xde,
    0x45, 0x67, 0x26, 0x6c, 0x60, 0xd3, 0x95, 0xf3, 0x1a, 0x7c, 0x0b, 0x09,
    0x40};

static void _test_verify(
    const char* cert_pem,
    const char* chain_pem,
    const oe_crl_t* crl[],
    size_t num_crl,
    bool revoked)
{
    oe_cert_t cert;
    oe_cert_chain_t chain;
    oe_verify_cert_error_t error = {0};
    oe_result_t r;

    r = oe_cert_read_pem(&cert, cert_pem, strlen(cert_pem) + 1);
    OE_TEST(r == OE_OK);

    r = oe_cert_chain_read_pem(&chain, chain_pem, strlen(chain_pem) + 1);
    OE_TEST(r == OE_OK);

    if (!crl)
        OE_TEST(num_crl == 0);

    if (crl)
        OE_TEST(num_crl > 0);

    r = oe_cert_verify(&cert, &chain, crl, num_crl, &error);

    if (revoked)
    {
        OE_TEST(r == OE_VERIFY_FAILED);

        /* Look for a revocation error message */
        {
            bool found = false;
            const char* messages[] = {
                "certificate revoked",
                "The certificate has been revoked (is on a CRL)",
            };

            for (size_t i = 0; i < OE_COUNTOF(messages); i++)
            {
                if (strstr(error.buf, messages[i]) == 0)
                {
                    found = true;
                    break;
                }
            }

            OE_TEST(found);
        }
    }
    else
    {
        OE_TEST(r == OE_OK);
    }

    oe_cert_free(&cert);
    oe_cert_chain_free(&chain);
}

static void _test_verify_with_crl(
    const char* cert_pem,
    const char* chain_pem,
    const uint8_t* crl_der,
    const size_t crl_der_size,
    bool revoked)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl;

    OE_TEST(oe_crl_read_der(&crl, crl_der, crl_der_size) == OE_OK);

    const oe_crl_t* crls[] = {&crl};
    _test_verify(cert_pem, chain_pem, crls, 1, revoked);

    OE_TEST(oe_crl_free(&crl) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_verify_without_crl(
    const char* cert_pem,
    const char* chain_pem)
{
    printf("=== begin %s()\n", __FUNCTION__);
    _test_verify(cert_pem, chain_pem, NULL, 0, false);
    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_get_dates(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl;

    OE_TEST(oe_crl_read_der(&crl, _CRL1, sizeof(_CRL1)) == OE_OK);

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

static void _test_verify_with_two_crls(
    const char* cert_pem,
    const char* chain_pem,
    const uint8_t* crl1_der,
    const size_t crl1_der_size,
    const uint8_t* crl2_der,
    const size_t crl2_der_size,
    bool revoked)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl1;
    oe_crl_t crl2;

    OE_TEST(oe_crl_read_der(&crl1, crl1_der, crl1_der_size) == OE_OK);
    OE_TEST(oe_crl_read_der(&crl2, crl2_der, crl2_der_size) == OE_OK);

    const oe_crl_t* crls[] = {&crl1, &crl2};
    _test_verify(cert_pem, chain_pem, crls, 2, revoked);

    OE_TEST(oe_crl_free(&crl1) == OE_OK);
    OE_TEST(oe_crl_free(&crl2) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestCRL(void)
{
    _test_verify_without_crl(_CERT1, _CHAIN1);
    _test_verify_without_crl(_CERT2, _CHAIN2);
    _test_verify_with_crl(_CERT2, _CHAIN2, _CRL2, sizeof(_CRL2), true);

    _test_verify_with_two_crls(
        _CERT2, _CHAIN2, _CRL2, sizeof(_CRL2), _CRL1, sizeof(_CRL1), true);

    _test_verify_with_two_crls(
        _CERT2, _CHAIN2, _CRL1, sizeof(_CRL1), _CRL2, sizeof(_CRL2), true);

    _test_get_dates();
}
