# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(DATA_DIR "../data")

if (UNIX)
add_executable(hostcrypto
    main.c
    ../../../common/rand.S
    ../read_file.c
    ../asn1_tests.c
    ../crl_tests.c
    ../ec_tests.c
    ../hash.c
    ../hmac_tests.c
    ../kdf_tests.c
    ../random_tests.c
    ../rdrand_test.c
    ../rsa_tests.c
    ../sha_tests.c
    ../tests.c
    ../utils.c)

# ========================= TestCRL & TestASN1 ================================

add_custom_command(TARGET hostcrypto
COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}
COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/sample.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/sample.cnf
COMMAND openssl ecparam -name prime256v1 -genkey -noout -out prime256v1-key.pem
COMMAND openssl req -config ${DATA_DIR}/sample.cnf  -new -x509 -key prime256v1-key.pem -out ${DATA_DIR}/asn1_cert.pem -subj "/CN=Intel SGX PCK Processor CA/O=Intel Corporation/L=Santa Clara/ST=CA/C=US" -sha256 -extensions v3_req
COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/intermediate.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/intermediate.cnf
COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/root.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/root.cnf
COMMAND openssl genrsa -out ${DATA_DIR}/RootCA.key.pem
COMMAND openssl req -new -x509 -key ${DATA_DIR}/RootCA.key.pem -out ${DATA_DIR}/RootCA.crt.pem -days 3650 -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Root" 
# Creating Intermediate certificates signed by the Root CA
COMMAND echo 'Creating Intermediate certificates signed by the root CA....'
COMMAND openssl genrsa -out ${DATA_DIR}/Intermediate.key.pem
COMMAND openssl req -new -key ${DATA_DIR}/Intermediate.key.pem -out ${DATA_DIR}/Intermediate.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Intermediate"
COMMAND openssl x509 -req -in ${DATA_DIR}/Intermediate.csr -CA ${DATA_DIR}/RootCA.crt.pem -CAkey ${DATA_DIR}/RootCA.key.pem -CAcreateserial -out ${DATA_DIR}/Intermediate.crt.pem -days 3650
# Creating Leaf certificates signed by the Root CA
COMMAND echo 'Creating Leaf certificates signed by the root CA....'
COMMAND openssl genrsa -out ${DATA_DIR}/Leaf.key.pem
COMMAND openssl req -new -key ${DATA_DIR}/Leaf.key.pem -out ${DATA_DIR}/Leaf.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Leaf"
COMMAND openssl x509 -req -in ${DATA_DIR}/Leaf.csr -CA ${DATA_DIR}/RootCA.crt.pem -CAkey ${DATA_DIR}/RootCA.key.pem -CAcreateserial -out ${DATA_DIR}/Leaf.crt.pem -days 3650

#  Setup Certificate Revocation lists for the following test cases
#  intermediade_crl is issued by Intermediate which revokes leaf cert
#  root_crl is issued by Root which revokes leaf cert

COMMAND touch intermediate_index.txt
COMMAND touch root_index.txt
COMMAND echo "00" > intermediate_crl_number
COMMAND echo "00" > root_crl_number

COMMAND openssl ca -gencrl -config ${DATA_DIR}/intermediate.cnf -out ${DATA_DIR}/intermediate_crl.pem
COMMAND openssl ca -gencrl -config ${DATA_DIR}/root.cnf -out ${DATA_DIR}/root_crl.pem

COMMAND openssl ca -revoke ${DATA_DIR}/Leaf.crt.pem -keyfile ${DATA_DIR}/Intermediate.key.pem -cert ${DATA_DIR}/Intermediate.crt.pem -config ${DATA_DIR}/intermediate.cnf
COMMAND openssl ca -revoke ${DATA_DIR}/Leaf.crt.pem -keyfile ${DATA_DIR}/RootCA.key.pem -cert ${DATA_DIR}/RootCA.crt.pem -config ${DATA_DIR}/root.cnf

COMMAND openssl ca -gencrl -config ${DATA_DIR}/intermediate.cnf -out ${DATA_DIR}/intermediate_crl.pem
COMMAND openssl ca -gencrl -config ${DATA_DIR}/root.cnf -out ${DATA_DIR}/root_crl.pem

COMMAND openssl crl -inform pem -outform der -in ${DATA_DIR}/intermediate_crl.pem -out ${DATA_DIR}/intermediate_crl.der
COMMAND openssl crl -inform pem -outform der -in ${DATA_DIR}/root_crl.pem -out ${DATA_DIR}/root_crl.der

# Take UTC date and time of intermediate_crl for _test_get_dates
COMMAND date -u +%Y:%m:%d:%H:%M:%S -r ${DATA_DIR}/intermediate_crl.pem > ${DATA_DIR}/time.txt

# ========================= TestEC ================================

COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/ec_cert_with_ext.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/ec_cert_with_ext.cnf
COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/ec_crl_distribution.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/crl_distribution.cnf
COMMAND openssl ecparam -name prime256v1 -genkey -noout -out ${DATA_DIR}/cert_with_ext-key.pem
COMMAND openssl req -config ${DATA_DIR}/ec_cert_with_ext.cnf  -new -x509 -key ${DATA_DIR}/cert_with_ext-key.pem -out ${DATA_DIR}/ec_cert_with_ext.pem -subj "/CN=Intel SGX PCK Processor CA/O=Intel Corporation/L=Santa Clara/ST=CA/C=US" -sha256 -extensions v3_req

COMMAND openssl ecparam -name prime256v1 -genkey -noout -out ${DATA_DIR}/crl_distribution-key.pem
COMMAND openssl req -config ${DATA_DIR}/crl_distribution.cnf  -new -x509 -key ${DATA_DIR}/crl_distribution-key.pem -out ${DATA_DIR}/ec_cert_crl_distribution.pem -subj "/CN=Intel SGX PCK Processor CA/O=Intel Corporation/L=Santa Clara/ST=CA/C=US" -sha256 -extensions v3_req

COMMAND openssl ecparam -name prime256v1 -genkey -noout -out ${DATA_DIR}/Rootec.key.pem
COMMAND openssl req -new -x509 -key ${DATA_DIR}/Rootec.key.pem -out ${DATA_DIR}/Rootec.crt.pem -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Rootec"
COMMAND openssl ecparam -name prime256v1 -genkey -noout -out ${DATA_DIR}/Intermediate.ec.key.pem
COMMAND openssl req -new -key ${DATA_DIR}/Intermediate.ec.key.pem -out ${DATA_DIR}/Intermediate.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Intermediateec"
COMMAND openssl x509 -req -in ${DATA_DIR}/Intermediate.csr -CA ${DATA_DIR}/Rootec.crt.pem -CAkey ${DATA_DIR}/Rootec.key.pem -CAcreateserial -out ${DATA_DIR}/Intermediateec.crt.pem -days 3650

COMMAND openssl ecparam -name prime256v1 -genkey -noout -out ${DATA_DIR}/Leaf.ec.key.pem
COMMAND openssl req -new -key ${DATA_DIR}/Leaf.ec.key.pem -out ${DATA_DIR}/Leaf.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Leafec"
COMMAND openssl x509 -req -in ${DATA_DIR}/Leaf.csr -CA ${DATA_DIR}/Intermediateec.crt.pem -CAkey ${DATA_DIR}/Intermediate.ec.key.pem -CAcreateserial -out ${DATA_DIR}/Leafec.crt.pem -days 3650

COMMAND openssl ec -in ${DATA_DIR}/Rootec.key.pem -pubout -out ${DATA_DIR}/Rootec.public.key
COMMAND echo -n "abcdefghijklmnopqrstuvwxyz" > ${DATA_DIR}/test_sign_alphabet.txt
COMMAND openssl dgst -sha256 -sign ${DATA_DIR}/Rootec.key.pem -out  ${DATA_DIR}/test_ec_signature ${DATA_DIR}/test_sign_alphabet.txt

COMMAND openssl ec -in ${DATA_DIR}/Rootec.key.pem -pubout -outform DER -out ${DATA_DIR}/Rootec.pubkey.der
# Extract the coordinates from the ec public key
COMMAND tail -c 64 ${DATA_DIR}/Rootec.pubkey.der > ${DATA_DIR}/coordinates.bin

# ========================= TestRSA  ================================

COMMAND openssl genrsa -out ${DATA_DIR}/RootCA2.key.pem
COMMAND openssl req -new -x509 -key ${DATA_DIR}/RootCA2.key.pem -out ${DATA_DIR}/RootCA2.crt.pem -days 3650 -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Root2"

# Creating Intermediate certificates signed by the Root CA
COMMAND echo 'Creating Intermediate certificates signed by the root CA....'
COMMAND openssl genrsa -out ${DATA_DIR}/Intermediate2.key.pem
COMMAND openssl req -new -key ${DATA_DIR}/Intermediate2.key.pem -out ${DATA_DIR}/Intermediate2.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Intermediate2"
COMMAND openssl x509 -req -in ${DATA_DIR}/Intermediate2.csr -CA ${DATA_DIR}/RootCA2.crt.pem -CAkey ${DATA_DIR}/RootCA2.key.pem -CAcreateserial -out ${DATA_DIR}/Intermediate2.crt.pem -days 3650

# Extract Modules binary from Leaf Certificate
COMMAND openssl x509 -inform PEM -in ${DATA_DIR}/Leaf.crt.pem -outform DER | tail -c+304 | head -c256 > ${DATA_DIR}/Leaf_modules.bin

# Generate Public key from Private key
COMMAND openssl rsa -in ${DATA_DIR}/Leaf.key.pem -pubout -out ${DATA_DIR}/Leaf_public.key.pem

# Generate the hash Signature from Private key
COMMAND openssl dgst -sha256 -sign ${DATA_DIR}/Leaf.key.pem -out ${DATA_DIR}/test_rsa_signature ${DATA_DIR}/test_sign_alphabet.txt
)
else()
add_executable(hostcrypto
    main.c
    ../hash.c
    ../hmac_tests.c
    ../kdf_tests.c
    ../sha_tests.c
    ../tests.c
    ../utils.c)
endif()

target_link_libraries(hostcrypto oehost)
add_test(tests/crypto/host hostcrypto)
