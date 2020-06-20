Certificate based attestation: plugin model
=====================

This test validates the following OE public APIs:

* oe_generate_plugin_attestation_certificate
* oe_free_attestation_certificate, and
* oe_verify_attestation_certificate

Test scenario:

- **Host Side**
  1. Create an enclave
  2. Issue an ecall (get_tls_cert) into enclave for getting a self-signed certificate embedded with a plugin attestation report of the enclave
  3. Once the certificate is received, call oe_verify_attestation_cert to verify the certificate and report.

- **Enclave side**
  1. Implement get_tls_cert(), which calls oe_generate_plugin_attestation_cert API to generate a requested certificate
  2. Call oe_verify_attestation_cert on the generated certificate before returning from get_tls_cert call
