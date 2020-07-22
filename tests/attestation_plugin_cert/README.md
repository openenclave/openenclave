Certificate based attestation: with evidences
=====================

This test validates the following OE public APIs:

* oe_get_attestation_certificate_with_evidence
* oe_free_attestation_certificate, and
* oe_verify_attestation_certificate_with_evidence

Test scenario:

- **Host Side**
  1. Create an enclave
  2. Issue an ecall (get_tls_cert) into enclave for getting a self-signed certificate embedded with evidence in a specific format
  3. Once the certificate is received, call oe_verify_attestation_certificate_with_evidence to verify the certificate.

- **Enclave side**
  1. Implement get_tls_cert(), which calls oe_get_attestation_certificate_with_evidence API to generate a requested certificate
      based on a given format UUID
  2. Call oe_verify_attestation_certificate_with_evidence on the generated certificate before returning from get_tls_cert call
