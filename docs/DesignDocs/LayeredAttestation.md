# Open Enclave Layered Claimsets Proposal

## Background

As explained in Section 3 of the
[IETF Remote Attestation Procedures Architecture](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/),
attestation evidence can consist of multiple claim sets, either for layered components
or for multiple parts of a composite device.

Today, the Verifier APIs (`oe_verify_evidence`) in the Open Enclave SDK only support
a very limited set of evidence types.  Specifically, it only supports up to three total
claimsets: the main claimset for the enclave itself, a claimset for run-time custom 
claims, and potentially a claimset for init-time custom claims.  All of these are claims
about the enclave's code and data, and do not support multiple claim sets below the
enclave, as is required by OP-TEE, the 
[IETF Entity Attestation Token (EAT)](https://datatracker.ietf.org/doc/draft-ietf-rats-eat/),
the Trusted Computing Group's DICE standard, etc.

For the Open Enclave SDK to be truly TEE agnostic and work with OP-TEE and other TEEs
beyond SGX, the API needs to change to accommodate more flexibility.

There has been much IETF discussion around the IETF EAT format in order to get it to
be flexible enough to express the various cases mentioned above (including SGX).
An EAT contains a claim set, where besides normal claims, it may contain a list of 0
or more "submodules" where each submodule consists of an id (or name), and a claim set.

## Sample Cases

Let's briefly discuss a couple of cases and how they would be handled with EATs.

### Case 1: Layered Attestation with Nested Claim Sets

In this example, each claim set is fully contained within another claim set, until
the root is reached.  OE's current organization where run-time
custom claims and init-time custom claims are contained inside the main claim set,
is a special case of this.  Any number of such claim sets could be contained in the
main claim set.

Unlike OE's current organization, however, there can be any number of layers of nesting,
and the main claim set is not necessarily the one for MRENCLAVE, but could instead be
one for Arm Trusted Firmware, where the equivalent of the MRENCLAVE claim set might be
multiple layers deep in the evidence, as in the RATS Architecture example.

### Case 2: Layered Attestation with Hashed Claim Sets

In this example, there are multiple claim sets as in Case 1, but rather than nesting
a claim set in another one, only a hash of the claim set is nested in another claim set.
From a security perspective, as long as the hash is as strong as signing the claims
themselves would be, this approach is as strong as case 1.

The encoding is, however, different from case 1 in that multiple claim sets are
returned in parallel rather than just one root.

This is the approach taken by typical certificate chains, and any certificate
chain API (whether OpenSSL's, Windows's, or otherwise) will reflect this type of
organization, where an array of certificates is used.

### Case 3: Composite Devices

In this example, there are multiple claim sets as in Case 2, except that none contains
a hash of any other claim sets.  Hence, similar to case 2, multiple claim sets
are returned in parallel rather than just one root.  This is the case discussed
in section 3.2 of the RATS Architecture.

### Case 4: Hybrid

In cases 1-3, all claim sets fell into the same case.  However, this is not necessary
and in general a device might have a much of multiple cases above, or even all three.
Hence, the flexibility must be on a per claim set basis, as it is in the EAT format.
In IETF parlance, an array of EATs where each EAT may have submodules (each of
which in turn may have other submodules, etc.) provides the full flexibility of
all these cases.

## Open Enclave API Proposal

A claim set is currently represented in many APIs by an array of claims expressed
by the following pair of arguments:
```
   oe_claim_t** claims,
   size_t* claims_length
```

For example, the current experimental Verifier API is:
```
oe_result_t oe_verify_evidence(
    const oe_uuid_t* format_id,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length);
```

This problem with this simplistic API is that it can only support Case 1, and not
the other cases which require multiple claim sets in parallel.

Thus, we propose defining:
```
typedef struct _oe_claim_set
{
    oe_claim_t** claims;
    size_t* claims_length;
} oe_claim_set_t;
```

The Verifier API would become:
```
oe_result_t oe_verify_evidence_v2(
    const oe_uuid_t* format_id,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_set_t** claim_sets,
    size_t* claim_set_length);
```

### Opportunities for deprecation

TODO: evaluate which, if any, existing APIs or structures could be
marked for deprecation as being superceded by the claim set design.
