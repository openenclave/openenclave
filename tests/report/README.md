OE_GetReport API tests
=====================

Test behavior of OE_GetReport, OE_ParseReport, OE_VerifyReport APIs:

- **Host Side**
  1. *TestLocalReport* : Tests reportData scenarios (null, partial, full), optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  1. *TestRemoteReport* : Tests reportData scenarios (null, partial, full), null optParams, small report buffer scenarios, and succeeding invocations.
  1. *TestLocalVerifyReport*: Tests OE_VerifyReport on locally attested reports. No, partial and full report data scenarios. Negative test.


- **Enclave side**
  1. *TestLocalReport* : Tests reportData scenarios (null, partial, full), optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  1. *TestRemoteReport* : Tests reportData scenarios (null, partial, full), null optParams, small report buffer scenarios, and succeeding invocations.
    1. *TestLocalVerifyReport*: Tests OE_VerifyReport on locally attested reports. No, partial and full report data scenarios. Negative test.
