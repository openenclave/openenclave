## Open Enclave Init-time Configuration Interface.
This document describes how developers can set CONFIGID and CONFIGSVN fields from the host side software at enclave initialization time and retrieve same information on enclave software side.
[Overview of SGX CONFIGID and CONFIGSVN](https://github.com/openenclave/openenclave/blob/cd72fd7069488ba6f453c8f5f47bd9fd9a6e6c0d/docs/DesignDocs/InitTimeConfigurationInterface.md#sgx-configid-and-configsvn-overview).
#### Setting CONFIGID and CONFIGSVN at enclave initialization time

CONFIGID and CONFIGSVN information is passed in to the enclave creation settings argument with setting type `OE_SGX_ENCLAVE_CONFIG_DATA` and configuration data with data type `oe_sgx_enclave_setting_config_data`. Line number 39-47 [here](https://github.com/openenclave/openenclave/blob/master/tests/config_id/host/host.c) demonstrates how CONFIGID and CONFIGSVN is filled in `oe_sgx_enclave_setting_config_data` type and setting is passed to enclave creation time [here]('https://github.com/openenclave/openenclave/blob/master/tests/config_id/host/host.c#L61').

To make CONFIGID and CONFIGSVN information as part of enclave initialization data, the underlying hardware should support KSS feature which is available from Intel Icelake family CPUs. (Not available in Cofee family CPUs.). Developers can check if KSS feature is available or not using function `_is_kss_supported` [here](https://github.com/openenclave/openenclave/blob/master/tests/config_id/host/host.c#L59).
Users can make setting CONFIGID and CONFIGSVN as optional using `ignore_if_unsupported` field in `oe_sgx_enclave_setting_config_data` to `true` as shown [here](https://github.com/openenclave/openenclave/blob/master/tests/config_id/host/host.c#L49). By using  `ignore_if_unsupported` field and making settings as optional users can make sure that enclave creation will not fail on Coffelake CPUs.

#### Retrieving CONFIGID and CONFIGSVN on enclave side:
This file [here](https://github.com/openenclave/openenclave/blob/master/tests/config_id/enc/enc.c#L32) describes how CONFIGID and CONFIGSVN information can be retrieved on enclave side using `oe_get_evidence`, `oe_verify_evidence` and `_find_claims`.
