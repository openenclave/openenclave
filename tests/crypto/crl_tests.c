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
    "MIIDrjCCApagAwIBAgIJAKs+hBG7YNB9MA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNV\n"
    "BAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdSZWRtb25kMSEw\n"
    "HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxITAfBgNVBAMMGG9lY3J5\n"
    "cHRvdGVzdGludGVybWVkaWF0ZTAeFw0xODA5MDYxODQ4MTBaFw0xODEwMDYxODQ4\n"
    "MTBaMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQH\n"
    "DAdSZWRtb25kMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxJTAj\n"
    "BgNVBAMMHGxlYQgICBtbQxtbQxtbQ2YyY3J5cHRvdGVzdHMwggEiMA0GCSqGSIb3\n"
    "DQEBAQUAA4IBDwAwggEKAoIBAQDGN4EkYmyM3ymrqngh4idhQasMem+QC1WVkZqn\n"
    "Wjr7/0fjvOJNcRiKW6fZth4wTHdDif+2TUau+nLh/jQnD5nHDVEewncBIrdLMxpa\n"
    "gL9jUorCL7BWrLG2YDGtvRAc3R6zHUc8OIwQHLmauqQTN4wYtmr/0gQ9aU/NS11k\n"
    "XbVf0cYRazgVu3lXLyDOjg+WhppcOR8tXBwb8vjjKp7rqogNIq9baoPMUTML3PHN\n"
    "UPoDBtqRaT7DnKJgoipBYVUyjjWMeXGJs0jZb3t4vkKJtKBonMKPMZibsU+y+YPr\n"
    "SUtBKdbmaHtW7lJ7x2qM/Jl+CAB63YCaxwDZTKoVTv1Q82iTAgMBAAGjMzAxMC8G\n"
    "A1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcnlwdG90ZXN0cy9sZWFmMmNybHVybDAN\n"
    "BgkqhkiG9w0BAQsFAAOCAQEAkkdT27JGAdZlHKFw/5N5AC0qWPzwVyGe2TVZfvrW\n"
    "pejqnBjCe1b3kICdYacalUxbJ5NWw027cmmvJuZtTljahvQXnsOrQspGbWcuzGk6\n"
    "6bBNp1NCUizMv3v5v8xi6k6FV2wLMArnZcDP0n6S6tSCIx1HVGJnlbTDEnhBEbA8\n"
    "j0Hk7ZcrIavJKiTUHYjiYDxg3hlYeT8Avk2wGrISRu50uOrf7L5kNTF3NKqK1kf1\n"
    "vygF5PGkVOMOKdiu/8y8rYMn1rWY+5lYzMIXLAMhuYVWm3YcTMqvjGksgvgI8ucG\n"
    "aLguxwf8hDtbTLYwYGGlRu6ynOzM2FbEnj3zCPBQ0TveHw==\n"
    "-----END CERTIFICATE-----\n";

static const char _CHAIN2[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDaDCCAlACCQDl0tZ05w6gGjANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJV\n"
    "UzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHUmVkbW9uZDEhMB8GA1UE\n"
    "CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRkwFwYDVQQDDBBvZWNyeXB0b3Rl\n"
    "c3Ryb290MB4XDTE4MDgyOTIxMTMxN1oXDTE4MDkyODIxMTMxN1owejELMAkGA1UE\n"
    "BhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1JlZG1vbmQxITAf\n"
    "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEhMB8GA1UEAwwYb2Vjcnlw\n"
    "dG90ZXN0aW50ZXJtZWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"
    "AQEA4OGVvLKwEmXtO0DfxNzIR+Bh6E/+LaXmk2s7GUZBaTqDrVCNTVeFBSww/2kF\n"
    "/cmfAuS0NQB+/cJUV1W1bBs6deAJa8EwalyE2HJF4bgL6lKSF/XQmYDWHHrhF47W\n"
    "vRPaDWIdAfWZgGtCklh6tXtieCd3wvFQLqH5/y7lT94jrHawMhmM+4Nj4OPN/vDg\n"
    "1LlkyJvcbLNdav74gk1QXmdACKLEdS/uzma9E3EE+TS1FbzX1IqM0IRNT5qFjTz3\n"
    "yNUmc5Ps0OqPgrt2UavJXNhX9X95UyFXm/uupA1SaT25FNE8FAvTTygkgE036Z9p\n"
    "Earx37iu1xf48MT2+rAOVNh05QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBR9fJo\n"
    "2cX1qkym2aE/v6GeSWOf8exqVlZkoozd1c1NSe3D8PUXDZmDGEQHegz2AXyTDQMV\n"
    "WQJq0dDcibnD/Ong9x1bKZxC/wFGXdGrQLqiAwBKqnEfjy96ZZzixfuyuzoZS+tG\n"
    "iCI5+bWO2mi98EuNml/4ixS1Tus5FS4/nCni6X0gRsn1w6TCHgxcQCSCtUrwGEfw\n"
    "9zzYn57Vj1R2HlsBpDY0/jMPDSzvS6uBy8Trbemz1TMfMqV8iImLPneYn/M6d0Bu\n"
    "SWLGhZ2lKquTl6b4Ymarb0vq27RPYfL1tyUd5+hBNCtUTDQtB9Vy9KZxOWhFl6uq\n"
    "jsUHa3HHe+Po/jAP\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDtzCCAp+gAwIBAgIJAMHPfNZggxxqMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNV\n"
    "BAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdSZWRtb25kMSEw\n"
    "HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxGTAXBgNVBAMMEG9lY3J5\n"
    "cHRvdGVzdHJvb3QwHhcNMTgwODI5MjExMjEyWhcNMTgwOTI4MjExMjEyWjByMQsw\n"
    "CQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHUmVkbW9u\n"
    "ZDEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRkwFwYDVQQDDBBv\n"
    "ZWNyeXB0b3Rlc3Ryb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
    "t9nT1nXvphxjwo/XJkhJHdM+mQEM/rFuFid5v5291XCh0RMsu3X5uRY/FiiZ3Yhr\n"
    "0CfmqEczYp/NK4vhPCjEmOwhuBTTgrE4OaDQmB1qbsrlXqykVCv8KpVyYS02bUGm\n"
    "IY+RRiypi6MJ8JiAN9JmNLo3XvTpwPkH7Icw+xjHpqFjqUp9JywfzR7pMI12qTP/\n"
    "TqL4bZlN+fnBZLbYoDXuBvBHGmlbhrvq43+kqX7go5nbfJh1PMKcFA1yzm2hsxn2\n"
    "LLqpvMULVWXwRuZ1g2L6jM9/tdvgaJEVzVwPZA22ne/AX+Ce9n/Q7pQOhy79ex6D\n"
    "W/9KEgyXV+cyAV8tnp9pqwIDAQABo1AwTjAdBgNVHQ4EFgQUrD6y+GE6a0+qur/L\n"
    "xmTq5LJCAr4wHwYDVR0jBBgwFoAUrD6y+GE6a0+qur/LxmTq5LJCAr4wDAYDVR0T\n"
    "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEANa5Slh1is7aQxIMeJ5ypASNjVxBG\n"
    "yi563CFkun7pgUOabCwnRfIoG29Ixvrv7/XCRYakPLBVZGNoZD/dmK0/R4+7Y8tr\n"
    "VRiaf8oPhJFzhDocGU8SvLPPvFuNpNg2dTbP6NvInIyEOILKxFDQ/O6n0zWAFPLX\n"
    "wzTid9VMdWBRSQAWZ4TWqIZGX1KwCGien4AVjC/wYsarcNT4I1u10xAuxGbFb5+7\n"
    "LMhtNXlQlYma59X4nWwbhoh0mpOxzfV2uFUx8HxJAX0Qom5eG+5WjiZc4lMBtgPG\n"
    "fIfqpbMxXtOBJh7PAVrYpoQXczLV3BFBzH7kNaOPQ5Y+7DaPpa/we1jnvQ==\n"
    "-----END CERTIFICATE-----\n";

/* This CRL contins _CERT2 */
static const uint8_t _CRL2[] = {
    0x30, 0x82, 0x01, 0xf1, 0x30, 0x81, 0xda, 0x02, 0x01, 0x01, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
    0x00, 0x30, 0x7a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f,
    0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07,
    0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31, 0x21, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e,
    0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50,
    0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x18, 0x6f, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74,
    0x6f, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65,
    0x64, 0x69, 0x61, 0x74, 0x65, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x39, 0x30,
    0x36, 0x31, 0x39, 0x30, 0x31, 0x33, 0x35, 0x5a, 0x17, 0x0d, 0x31, 0x38,
    0x31, 0x30, 0x30, 0x36, 0x31, 0x39, 0x30, 0x31, 0x33, 0x35, 0x5a, 0x30,
    0x1c, 0x30, 0x1a, 0x02, 0x09, 0x00, 0xab, 0x3e, 0x84, 0x11, 0xbb, 0x60,
    0xd0, 0x7d, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x39, 0x30, 0x36, 0x31, 0x39,
    0x30, 0x31, 0x30, 0x33, 0x5a, 0xa0, 0x0e, 0x30, 0x0c, 0x30, 0x0a, 0x06,
    0x03, 0x55, 0x1d, 0x14, 0x04, 0x03, 0x02, 0x01, 0x01, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x01, 0x00, 0x56, 0xec, 0xff, 0xad, 0x9c, 0x58, 0x74,
    0x0a, 0x33, 0x83, 0x2b, 0x5a, 0xcb, 0x0d, 0x45, 0x5d, 0xec, 0x1f, 0x2a,
    0xd5, 0x4a, 0xa5, 0x10, 0xaf, 0x9f, 0xa1, 0x2c, 0xe6, 0x1a, 0xa7, 0xcb,
    0x63, 0x3f, 0xcf, 0xd3, 0x63, 0x67, 0x62, 0xc9, 0x06, 0x9f, 0x9c, 0xee,
    0x09, 0xf1, 0xcc, 0x43, 0x7b, 0xc8, 0xd6, 0xa6, 0x23, 0x4f, 0xdf, 0x22,
    0x50, 0x7b, 0x02, 0x5e, 0xe7, 0xec, 0xd1, 0x35, 0x8b, 0x80, 0xf2, 0x7b,
    0x20, 0xf0, 0x41, 0xef, 0x16, 0xf9, 0xce, 0x4e, 0x25, 0x54, 0x71, 0xed,
    0xf5, 0x4c, 0x70, 0x36, 0x59, 0x3f, 0x87, 0xd2, 0x47, 0xe2, 0x51, 0xf9,
    0x5c, 0x8a, 0xc2, 0xd6, 0xfe, 0x0c, 0x39, 0x53, 0xaf, 0xd5, 0xe5, 0x85,
    0x1b, 0xc6, 0x26, 0x10, 0x1d, 0xb9, 0x8f, 0xfa, 0x51, 0x16, 0x32, 0x72,
    0x26, 0xa6, 0xaa, 0xa9, 0xd1, 0x67, 0xde, 0x7a, 0xba, 0xac, 0xb0, 0x0d,
    0xc3, 0xb2, 0x1d, 0x64, 0x71, 0x90, 0xcf, 0x8b, 0x84, 0xff, 0x19, 0x7e,
    0xcd, 0x31, 0x49, 0x6a, 0x53, 0xdb, 0x5f, 0x13, 0x70, 0x55, 0xb3, 0xab,
    0x1e, 0x37, 0x73, 0xa0, 0x71, 0x99, 0x44, 0x0b, 0x2b, 0xac, 0xc7, 0x45,
    0xd8, 0xbb, 0x29, 0xfd, 0xfc, 0x45, 0x2e, 0xf2, 0x02, 0xe7, 0xe2, 0xd2,
    0x76, 0x9c, 0x66, 0x67, 0x1d, 0xf8, 0xb8, 0x37, 0x59, 0xdf, 0xfc, 0x7a,
    0x0b, 0x1d, 0xc6, 0x57, 0xef, 0xeb, 0x20, 0x96, 0xc4, 0x0c, 0x71, 0x9f,
    0x56, 0xe4, 0xe1, 0x99, 0xed, 0xe4, 0x6e, 0xa0, 0xce, 0xec, 0x03, 0xd3,
    0xba, 0x62, 0x8d, 0x8a, 0x29, 0xc5, 0xa7, 0xfe, 0x75, 0xcf, 0xfb, 0x0a,
    0x58, 0x86, 0xfa, 0xfd, 0xb3, 0x6d, 0xa4, 0xa5, 0xdd, 0x40, 0x52, 0x3b,
    0xb2, 0x01, 0xdc, 0x06, 0xf6, 0x90, 0x71, 0x1f, 0xc5, 0xe8, 0x99, 0xb1,
    0x0d, 0x35, 0xd0, 0x4a, 0x5d, 0x27, 0xb4, 0xb5, 0x18,
};

static void _test_verify(
    const char* cert_pem,
    const char* chain_pem,
    const oe_crl_t* crl,
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

    r = oe_cert_verify(&cert, &chain, crl, &error);

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
    _test_verify(cert_pem, chain_pem, &crl, revoked);
    OE_TEST(oe_crl_free(&crl) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_verify_without_crl(
    const char* cert_pem,
    const char* chain_pem)
{
    printf("=== begin %s()\n", __FUNCTION__);
    _test_verify(cert_pem, chain_pem, NULL, false);
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
    _test_verify_without_crl(_CERT, _CHAIN);
    _test_verify_with_crl(_CERT, _CHAIN, _CRL, sizeof(_CRL), false);

    _test_verify_without_crl(_CERT2, _CHAIN2);
    _test_verify_with_crl(_CERT2, _CHAIN2, _CRL2, sizeof(_CRL2), true);

    _test_get_dates();
}
