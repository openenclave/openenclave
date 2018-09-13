Additional Crypto API tests
===========================

**Preparing Test Data**

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
  
**List of Tests**
  1. test_cert_chain_positive: 
        Asserts the following condition: "In a valid cert chain, each certificate's issuer CA occurs atleast once after the certificate".
        Tests correct ordering, duplicates, two and three level chains.
  2. test_cert_chain_negative: Negative tests involving incorrect ordering, missing certs etc.
        

