oe_generate_attestation_cert, oe_free_attestation_cert, and oe_verify_attestation_cert API tests
=====================

Test scenario:

- **Host Side**
  1. Create an enclave
  2. Issue an ecall (get_tls_cert) into enclave for getting a self-signed certificate embedded with an quote of the enclave
  3. Once the certificate is received, call oe_verify_attestation_cert to verify the certificate and quote
  

- **Enclave side**
  1. Implement get_tls_cert(), which calls oe_generate_attestation_cert API to generate a requested certificate
  2. Call oe_verify_attestation_cert on the generated certificate before returning from get_tls_cert call.

  
