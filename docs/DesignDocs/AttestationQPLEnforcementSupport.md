Attestation SGX QPL Enforcement Support
====

This proposal is to make a change to `oe_verify_evidence`, so that it can support policy-based SGX QPL (Quote Provider Library) specific enhancement, such as allowing Verifier applications to pass third party cloud specific parameters to the SGX QPL to allow them to do more advanced quote verification.

Motivation
----

Intel SGX rolls out PCK certificate and collateral information about every six months.
There is a scenario where a quote signed by the last version of PCK certificate cannot be verified with the latest version of collateral information.
This causes unnecessary attestation failures when new versions of PCK certificate and collateral information are rolled out.
To deal with this issue, the SGX QPL needs to return any version of collateral information based on additional query parameters (referred to as "baselines").
With that, a new API called `sgx_ql_get_quote_verification_collateral_with_params` was introduced in the SGX QPL.
Changes are also needed in the OE SDK's SGX plugin to call this new API.

Goals:
 - Verifier applications can call `oe_verify_evidence` and pass third party specific parameters to do customized verification.
 - Changing the contract for the additional parameters does not need OE SDK changes.

The contract for the additional parameters are between Verifier applications that use the OE SDK, and the SGX third party cloud collateral caching services.

User Experience
----

A new policy type `OE_POLICY_ENDORSEMENTS_BASELINE` is added to current policy types.
Only one policy of this type can be specified for `oe_verify_evidence` API.
The data for this policy is an opaque blob for OE SDK.

Specification
----

### New policy type

- `OE_POLICY_ENDORSEMENTS_BASELINE` in `oe_policy_type_t`
- The data for this policy is a blob.

### New OCall API

Though there are no API signature changes for `oe_verify_evidence`, one EDL based API needs to be added,
- New OCall `oe_get_quote_verification_collateral_with_baseline_ocall` to be added to sgx/attestation.edl, which will coexist with current API `oe_get_quote_verification_collateral_ocall` for backward compatibility.

### Code example

With the new policy, the OE SDK client will be able to pass in multiple collateral baseline parameters as below,
```C
// Please be noted, the data could be any format, this is just an
// example, the API does not have any assumption on the data format.
const char* parameters = "region=eastus&tcbevaluationdatanumber=1"
oe_policy_t policy;
policy.type = OE_POLICY_ENDORSEMENTS_BASELINE;
policy.policy_size = strlen(parameters) + 1;
policy.policy = parameters;

// Now, call oe_verify_evidence with policies
result = oe_verify_evidence(
            // The format ID is OE_FORMAT_UUID_LEGACY_REPORT_REMOTE for all OE
            // reports for remote attestation.
            &_uuid_legacy_report_remote,
            report,
            report_size,
            endorsements_buffer,
            endorsements_buffer_size,
            &policies,
            1,
            claims,
            claims_length);
```
