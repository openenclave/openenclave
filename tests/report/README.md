oe_get_report API tests
=====================

Test behavior of oe_get_report, oe_parse_report, oe_verify_report APIs:

- **Host Side**
  1. *TestLocalReport* : Tests optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  2. *TestRemoteReport* : Tests null optParams, small report buffer scenarios, and succeeding invocations.
  3. *TestLocalVerifyReport*: Tests oe_verify_report on locally attested reports. Negative test.
  4. *TestRemoteVerifyReport*: Tests oe_verify_report on remote attested reports. 


- **Enclave side**
  1. *TestLocalReport* : Tests reportData scenarios (null, partial, full), optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  2. *TestRemoteReport* : Tests reportData scenarios (null, partial, full), null optParams, small report buffer scenarios, and succeeding invocations.
  3. *TestLocalVerifyReport*: Tests oe_verify_report on locally attested reports. No, partial and full report data scenarios. Negative test.
  4. *TestRemoteVerifyReport*: Tests oe_verify_report on remote attested reports. Tests reportData scenarios (null, partial, full).

**Other tests**
  1. *TestVerifyTCBInfo*: Tests tcbInfo JSON processing. Positive and negative tests. Schema validation.
  2. *TestIso861Time*, *TestIso861TimeNegative*: Positive and negative tests oe_datetime_t.
  3. test_minimum_issue_date: Tests that setting the minimum crl, tcb issue date has the desired effect on attestation.
  
  
