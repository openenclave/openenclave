oe_get_report API tests
=====================

Test behavior of oe_get_report, oe_parse_report, oe_verify_report APIs:

- **Host Side**
  1. *TestLocalReport* : Tests reportData scenarios (null, partial, full), optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  1. *TestRemoteReport* : Tests reportData scenarios (null, partial, full), null optParams, small report buffer scenarios, and succeeding invocations.
  1. *TestLocalVerifyReport*: Tests oe_verify_report on locally attested reports. No, partial and full report data scenarios. Negative test.


- **Enclave side**
  1. *TestLocalReport* : Tests reportData scenarios (null, partial, full), optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  1. *TestRemoteReport* : Tests reportData scenarios (null, partial, full), null optParams, small report buffer scenarios, and succeeding invocations.
    1. *TestLocalVerifyReport*: Tests oe_verify_report on locally attested reports. No, partial and full report data scenarios. Negative test.

  **Other tests**
  1. *TestVerifyTCBInfo*: Tests tcbInfo JSON processing. Positive and negative tests. Schema validation.
