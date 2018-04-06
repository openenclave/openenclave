OE_GetReport API tests
=====================

Test behavior of OE_GetReport API:

- **Host Side**
  1. *TestLocalReport* : Tests reportData scenarios (null, partial, full), optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  1. *TestRemoteReport* : Tests reportData scenarios (null, partial, full), null optParams, small report buffer scenarios, and succeeding invocations.


- **Enclave side**
  1. *TestLocalReport* : Tests reportData scenarios (null, partial, full), optParams scenarios (null, valid target info), small report buffer scenarios, and succeeding invocations.
  1. *TestRemoteReport* : Tests reportData scenarios (null, partial, full), null optParams, small report buffer scenarios, and succeeding invocations.
