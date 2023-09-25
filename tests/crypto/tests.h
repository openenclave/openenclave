// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TESTS_CRYPTO_TESTS_H
#define _TESTS_CRYPTO_TESTS_H

void TestASN1(char* path);
void TestCRL(char* path);
#if defined(OE_BUILD_ENCLAVE)
void TestCert(void);
#endif
void TestEC(char* path);
void TestKDF(void);
void TestRandom(void);
void TestCpuEntropy(void);
void TestRSA(char* path);
void TestSHA(void);
void TestHMAC(void);
void TestAll(char* path);

#endif /* _TESTS_CRYPTO_TESTS_H */
