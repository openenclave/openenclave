# Testing OE standalone host attestation verification API where special hardware (like SGX) is not required.

## These APIs are part of oehostverify library. APIs (See host_verify.h):
 - oe_verify_remote_report
 - oe_verify_attestation_certificate


Test scenario:

- **Host Side**
  1. Auto-generate a valid attestation certificate (RSA and EC) and report using auto generated private/public keys.
     - If this test is run from a non-sgx machine, an outside process needs to generate these certs/report
  2. Copy invalid certificates and report from the data folder.
  3. Read certificates/report from file.
  4. Pass certificates to the oe_verify* functions.


