Additional Crypto API tests
===========================

==Preparing Test Data==

The certificates and CRLs were generated using the following openssl commands.

  1. Creating Root CA.
      1. openssl genrsa -out RootCA.key.pem
      2. openssl req -new -x509 -key RootCA.key.pem -out RootCA.crt.pem

  2. Creating Intermediate CA signed by the Root CA.
      1. openssl genrsa -out IntermediateCA.key.pem
      2. openssl req -new -key IntermediateCA.key.pem -out IntermediateCA.csr
      3. openssl x509 -req -in IntermediateCA.csr -CA RootCA.crt.pem -CAkey RootCA.key.pem -CAcreateserial -out IntermediateCA.crt.pem

  3. Creating Leaf certificate signed by the Intermediate CA.
      1. openssl genrsa -out Leaf.key.pem
      2. openssl req -new -key Leaf.key.pem -out Leaf.csr
      3. openssl x509 -req -in Leaf.csr -CA IntermediateCA.crt.pem -CAkey IntermediateCA.key.pem -CAcreateserial -out Leaf.crt.pem

  4. Setup CA index files and CRL numbers.
      1. touch root_index.txt
      2. touch intermediate_index.txt
      3. echo "00" > root_crl_number
      4. echo "00" > intermediate_crl_number

  5. Generating a root and intermediate CRLs
      1. openssl ca -gencrl -keyfile RootCA.key.pem -cert RootCA.crt.pem -out root_crl_n.pem -config root.cnf
      2. openssl ca -gencrl -keyfile IntermediateCA.key.pem -cert IntermediateCA.crt.pem -out intermediate_crl_n.pem -config intermediate.cnf

  6. Revoking intermediate and leaf certs.
      1. openssl ca -revoke IntermediateCA.crt.pem -keyfile RootCA.key.pem -cert RootCA.crt.pem -config root.cnf
      2. openssl ca -revoke Leaf.crt.pem -keyfile IntermediateCA.key.pem -cert IntermediateCA.crt.pem -config intermediate.cnf

  7. Converting crl from pem to der format.
      1. openssl crl -inform pem -outform der -in crl.pem -out crl.der
  
==List of Tests==

  1. test_cert_chain_positive
       Asserts the following condition: "In a valid cert chain, each certificate's issuer CA occurs atleast once after the certificate".
        Tests correct ordering, duplicates, two and three level chains.
  2. test_cert_chain_negative: Negative tests involving incorrect ordering, missing certs etc.
