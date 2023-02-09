Add Support of Interoperable TLS Proposal
====

# Motivation

The Interoperable Attested TLS proposal enables Interoperability among RA-TLS based libraries, so different libraries can be used on either end of a TLS session. This proposal aligns with relevant standards, and is readily extensible to support new TEEs and evidence formats.

This proposal has been reviewed in the CCC Attestation SIG, and the presentation is in the [CCC Attestation SIG github repo](https://github.com/CCC-Attestation/meetings/blob/main/materials/ShanweiCen_Interoperable_ATLS.pdf). The SIG has created a project [interoperable-ra-tls](https://github.com/ccc-attestation/interoperable-ra-tls) with design documents and discussions on interoperability tests. Please refer to the [design documents](https://github.com/CCC-Attestation/interoperable-ra-tls/tree/main/docs) for certificate and evidence formats definition.

The objective is to add support of this proposal while maintaining backward compatibility, so that existing API and legacy applications continue to work without impact.

# Design

This section describes a high level design for the API and their implementation to support the proposed cert and evidence formats while maintainging backward compatibility.

- Cert verification: API stays the same.
    - Existing API `oe_verify_attestation_certificate_with_evidence_v2()` detects the type of input X.509 cert (new or existing) based on the presence of their respective OIDs, and processes accordingly.
- Evidence verification: API stays the same.
    - Existing API `oe_verify_evidence()` detects claims-buffer and endorsement serialization scheme based on the first byte in their buffers.
        - claims-buffer serialization
            - CBOR: first byte indicates CBOR map of 1 or 2 entries, with value 0xa1 or 0xa2.
                - Note: CBOR codecs are available many languages, as listed in [cbor.io](http://cbor.io/impls.html).
            - Existing OE serialization: header `oe_custom_claims_header_t` first field is little-endian `uint64_t version`, version 1 => [0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00].
                - We can safely assume version number is always less than 0x80.
        - Endorsement serialization
            - CBOR: first byte indicates a CBOR tag, with value 0xCX or 0xDX.
            - OE-style, endorsements: header `oe_endorsements_t` first field is `uint32_t version`, version 1 => [0x01 0x00 0x00 0x00].
                - We can safely assume the version number to be always less than 0x80.
- Evidence generation: add new flag to existing API.
    - CBOR serialization library: CBOR codecs are available many languages, as listed in [cbor.io](http://cbor.io/impls.html). 
    - API `oe_get_evidence(const oe_uuid_t* format_id, uint32_t flags, const void* custom_claims_buffer, ..., uint8_t* endorsements_buffer, ...)`: add a flag, such as `OE_EVIDENCE_FLAGS_CBOR_SERIALIZATION`, to indicate generating new format evidence. Input `custom_claims_buffer` must be in in CBOR serialization, and output `endorsements_buffer` in CBOR serialization
- Cert generation: add new API
    - Add new API, such as `oe_get_attestation_certificate_with_evidence_v2_dice()`, to generates a new cert with the proposed extensions.
        - Note: recommend to use stronger key pairs for the new certs, such as RSA3072 or EC384.

# Authors

- Shanwei Cen (@shnwc)
