# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../common/crypto_crls_cert_chains.edl host gen)

add_executable(crypto-extra_host host.cpp ${gen})

set(DATA_DIR "../data")

add_custom_command(TARGET crypto-extra_host
            COMMAND rm -rf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}
            COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}

            # x509 V3 extensions required to be able to validate cert chains using a self signed root cert and intermediate cert signed by the root cert. 
            # SSL1.1 no longer allows signing certs without the necessary v3 extensions.
            COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/root_v3.ext ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/root_v3.ext
            COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/intermediate_v3.ext ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/intermediate_v3.ext

            COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/root.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/root.cnf
            COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/root2.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/root2.cnf
            COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/intermediate.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/intermediate.cnf
            COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_SOURCE_DIR}/${DATA_DIR}/intermediate2.cnf ${CMAKE_CURRENT_BINARY_DIR}/${DATA_DIR}/intermediate2.cnf

            # The rest of the custom commands create a set of certificates for validating the OE certificate functions. 
            # It eliminates the need to check-in hardcoded certificates in the source tree
            # The certificates and CRLs were generated using the following openssl commands.
            # Creating Root CA private key and self-signed Root CA cert
            COMMAND openssl genrsa -out ${DATA_DIR}/RootCA1.key.pem
            COMMAND openssl req -new -x509 -key ${DATA_DIR}/RootCA1.key.pem -out ${DATA_DIR}/RootCA1.crt.pem -days 3650 -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Root"

            # We want to generate certificates used in this tests with at least one second apart to make it possible to sort those certificate by time 
            # "Not Before" of a x509 certificate, which has time resolution up to second 
            # Creating Intermediate CA certificate, signed by the Intermediate CA
            COMMAND sleep 1
            COMMAND openssl genrsa -out ${DATA_DIR}/IntermediateCA1.key.pem
            COMMAND openssl req -new -key ${DATA_DIR}/IntermediateCA1.key.pem -out ${DATA_DIR}/IntermediateCA1.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Intermediate"
            COMMAND openssl x509 -req -in ${DATA_DIR}/IntermediateCA1.csr -CA ${DATA_DIR}/RootCA1.crt.pem -CAkey ${DATA_DIR}/RootCA1.key.pem -CAcreateserial -out ${DATA_DIR}/IntermediateCA1.crt.pem -days 3650 -extfile ${DATA_DIR}/intermediate_v3.ext

            # Creating Leaf certificates signed by the Intermediate CA
            # Creating Leaf certificates signed by the Intermediate CA
            COMMAND sleep 1
            COMMAND echo 'Creating Leaf certificates signed by the Intermediate CA....'
            COMMAND openssl genrsa -out ${DATA_DIR}/Leaf1.key.pem
            COMMAND openssl req -new -key ${DATA_DIR}/Leaf1.key.pem -out ${DATA_DIR}/Leaf1.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Leaf1"
            COMMAND openssl x509 -req -in ${DATA_DIR}/Leaf1.csr -CA ${DATA_DIR}/IntermediateCA1.crt.pem -CAkey ${DATA_DIR}/IntermediateCA1.key.pem -CAcreateserial -out ${DATA_DIR}/Leaf1.crt.pem -days 3650

            COMMAND sleep 1
            COMMAND openssl genrsa -out ${DATA_DIR}/Leaf2.key.pem
            COMMAND openssl req -new -key ${DATA_DIR}/Leaf2.key.pem -out ${DATA_DIR}/Leaf2.csr -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Leaf2"
            COMMAND openssl x509 -req -in ${DATA_DIR}/Leaf2.csr -CA ${DATA_DIR}/IntermediateCA1.crt.pem -CAkey ${DATA_DIR}/IntermediateCA1.key.pem -CAcreateserial -out ${DATA_DIR}/Leaf2.crt.pem -days 3650

            # Setup Certificate Revocation lists for the following test cases
            #  root_crl1 and root_crl2 are issued by root.
            #  root_crl1 revokes no certificates.
            #  root_crl2 revokes intermediate cert.
            #  intermediate_crl1 and intermediate_crl2 are issued by intermediate.
            #  intermediate_crl1 revokes no certificates.
            #  intermediate_crl2 revokes leaf2.

            COMMAND touch root_index.txt
            COMMAND touch root_index2.txt
            COMMAND touch intermediate_index.txt
            COMMAND touch intermediate_index2.txt
            COMMAND echo "00" > root_crl_number
            COMMAND echo "00" > root_crl_number2
            COMMAND echo "00" > intermediate_crl_number
            COMMAND echo "00" > intermediate_crl_number2

            # Generating a root and intermediate CRLs
            COMMAND openssl ca -gencrl -config ${DATA_DIR}/root.cnf -out ${DATA_DIR}/root_crl1.pem 
            COMMAND openssl ca -gencrl -config ${DATA_DIR}/root2.cnf -out ${DATA_DIR}/root_crl2.pem
            COMMAND openssl ca -gencrl -config ${DATA_DIR}/intermediate.cnf -out ${DATA_DIR}/intermediate_crl1.pem
            COMMAND openssl ca -gencrl -config ${DATA_DIR}/intermediate2.cnf -out ${DATA_DIR}/intermediate_crl2.pem

            # Revoking intermediate and leaf certs
            COMMAND openssl ca -revoke ${DATA_DIR}/IntermediateCA1.crt.pem -keyfile ${DATA_DIR}/RootCA1.key.pem -cert ${DATA_DIR}/RootCA1.crt.pem -config ${DATA_DIR}/root2.cnf
            COMMAND openssl ca -revoke ${DATA_DIR}/Leaf2.crt.pem -keyfile ${DATA_DIR}/IntermediateCA1.key.pem -cert ${DATA_DIR}/IntermediateCA1.crt.pem -config ${DATA_DIR}/intermediate2.cnf

            # recreate updated CRL lists
            COMMAND openssl ca -gencrl -config ${DATA_DIR}/root2.cnf -out ${DATA_DIR}/root_crl2.pem
            COMMAND openssl ca -gencrl -config ${DATA_DIR}/intermediate2.cnf -out ${DATA_DIR}/intermediate_crl2.pem

            # Converting crl from pem to der format.
            COMMAND openssl crl -inform pem -outform der -in ${DATA_DIR}/root_crl1.pem -out ${DATA_DIR}/root_crl1.der
            COMMAND openssl crl -inform pem -outform der -in ${DATA_DIR}/root_crl2.pem -out ${DATA_DIR}/root_crl2.der
            COMMAND openssl crl -inform pem -outform der -in ${DATA_DIR}/intermediate_crl1.pem -out ${DATA_DIR}/intermediate_crl1.der
            COMMAND openssl crl -inform pem -outform der -in ${DATA_DIR}/intermediate_crl2.pem -out ${DATA_DIR}/intermediate_crl2.der
            )

target_include_directories(crypto-extra_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(crypto-extra_host oehostapp)
