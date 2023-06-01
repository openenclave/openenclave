// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TESTS_CRYPTO_TESTS_H
#define _TESTS_CRYPTO_TESTS_H

void TestASN1(void);
void TestCRL(void);
#if defined(OE_BUILD_ENCLAVE)
void TestCert(void);
#endif
void TestEC(void);
void TestKDF(void);
void TestRandom(void);
void TestCpuEntropy(void);
void TestRSA(void);
void TestSHA(void);
void TestHMAC(void);
void TestAll(void);

#endif /* _TESTS_CRYPTO_TESTS_H */
