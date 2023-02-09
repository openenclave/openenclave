# Testing OE standalone host attestation verification API where special hardware (like SGX) is not required.

## These APIs are part of oehostverify library. APIs (See host_verify.h):
 - oe_verify_remote_report
 - oe_verify_attestation_certificate
 - oe_verify_evidence


Test scenario:

- **Host Side**
  1. Auto-generate:
    - a valid attestation certificate (RSA and EC),
    - a report using auto generated private/public keys, and
    - evidence and endorsement files.
    - If this test is run from a machine without a TEE, an outside process needs to generate these certs/report.
  2. Copy invalid certificates and report from the data folder.
  3. Read certificates/report/evidence from file.
  4. Pass certificates/report/evidence to the oe_verify* functions and check their results.
