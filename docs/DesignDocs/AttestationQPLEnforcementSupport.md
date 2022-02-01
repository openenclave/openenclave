Attestation SGX QPL Enforcement Support
====

This proposal is to make a change to `oe_verify_evidence`, so that it can support policy-based SGX QPL (Quote Provider Library) specific enhancement, such as allowing the API user to pass data to the SGX QPL for more advanced quote verification.

Motivation
----

Intel SGX rolls out PCK certificate and collateral information about every six month. There is a scenario that a quote is signed by the last version of PCK certificate cannot be verified with the latest version of collateral information. This causes unnecessary attestation failures when new versions of PCK certificate and collateral information are rolled out. To deal with this issue, the SGX QPL need to return any version collateral information based on additional query parameters (referred as baselines). With that, a new API called `sgx_ql_get_quote_verification_collateral_with_params` is introduced in the SGX QPL. Changes are also needed at OE SDK to call this new API.

Goals:
 - Verifier can call `oe_verify_evidence` and pass SGX QPL specific parameters to do more advanced quote verification.

User Experience
----

A new policy type `OE_POLICY_SGX_COLLATERAL_BASELINE` is added to current policy types. Quote verifier can pass multiple policies with this type, while OE SDK would pass all the policies down to the SGX QPL API without interpreting the data content.

Specification
----

### New policy type & its data structure

- `OE_POLICY_SGX_COLLATERAL_BASELINE` in `oe_policy_type_t`
- `oe_sgx_collateral_query_param`, which is defined as below,
```C
// defined by SGX QPL
#define MAX_PARAM_STRING_SIZE (255)
typedef struct _oe_sgx_collateral_query_param
{
uint8_t key[MAX_PARAM_STRING_SIZE+1];
uint8_t value[MAX_PARAM_STRING_SIZE+1];
} oe_sgx_collateral_query_param_t;
```

### New APIs / OCalls

Though there is no API signature changes for `oe_verify_evidence`, some internal APIs that potentially get used by tools need to be changed. For backward compatibility, the following new APIs will be added to ensure all existing code either build from OE SDK headers and libraries or source directly can still work,
- `oe_get_sgx_endorsements_with_policies`, after change, this API will be called by existing `oe_get_sgx_endorsements` without any policy. This new API will not be exposed to OE SDK users.
- `oe_get_quote_verification_collateral_with_params_ocall`, the current API is `oe_get_quote_verification_collateral_ocall` is an API defined in sgx/attestation.edl, which could have been used by user enclaves, so need to bring this new API to work with existing API.

### Code example

With the new policy, the OE SDK client will be able to pass in multiple collateral baseline parameters as below,
```C
oe_sgx_collateral_query_param_t* baselines = (oe_sgx_collateral_query_param_t*)malloc(sizeof(oe_sgx_collateral_query_param_t) * 2);
memcpy_s(baselines[0].key, MAX_PARAM_STRING_SIZE + 1, "key1", strlen("key1") + 1);
memcpy_s(baselines[0].value, MAX_PARAM_STRING_SIZE + 1, "value1", strlen("value1") + 1);
memcpy_s(baselines[1].key, MAX_PARAM_STRING_SIZE + 1, "key2", strlen("key2") + 1);
memcpy_s(baselines[1].value, MAX_PARAM_STRING_SIZE + 1, "value2", strlen("value2") + 1);
oe_policy_t policies[2];
policies[0].type = OE_POLICY_SGX_COLLATERAL_BASELINE;
policies[0].policy = &baselines[0];
policies[0].policy_size = sizeof(oe_sgx_collateral_query_param_t);
policies[1].type = OE_POLICY_SGX_COLLATERAL_BASELINE;
policies[1].policy = &baselines[1];
policies[1].policy_size = sizeof(oe_sgx_collateral_query_param_t);

// Now, call oe_verify_evidence with policies
result = oe_verify_evidence(
            // The format ID is OE_FORMAT_UUID_LEGACY_REPORT_REMOTE for all OE
            // reports for remote attestation.
            &_uuid_legacy_report_remote,
            report,
            report_size,
            endorsements_buffer,
            endorsements_buffer_size,
            policies,
            2,
            claims,
            claims_length);
```


Alternatives
----

Since there could be other parameters required by QPL in future, the new policy type can be named to `OE_POLICY_QPL_PARAMETER`, which makes the policy more generic and the verifier can call `oe_verify_evidence` with arbitrary number of parameters with data format confronts to
```C
typedef struct _oe_qpl_parameter {
    uint32_t tag;
    uint8_t data[0];
} oe_qpl_parameter;
```

With this, OE SDK will blindly pass all the parameters to all QPL APIs and QPL APIs need to use the `tag` for each parameter to figure out the parameters that they can take and also the format for the data in parameter. **However, this requires the OE SDK users know about the concept of QPL as well as the tag and data contract for each provider.** Therefore, this alternative design is not preferred.