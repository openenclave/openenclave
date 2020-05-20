# Proposed Attestation API Requirements

This design document proposes requirements for APIs that applications can
use for performing attestation of enclave applications.

## Motivation

Requirements:
* Usable by Attesters, Verifiers, and Relying Parties
* Able to support different TEEs
* Able to support platforms of different endianness
* Able to support different protocols
* Able to support different topological models
  (e.g., Passport model vs Background-check model)
* Able to support different Evidence formats
* Able to support different Attestation Results formats
* Able to support different Verifier services, including a local Verifier
  on the same device as an Attester and/or a Relying Party
* Able to support Verifiers and Relying Parties that might or might not run
  in an enclave
* Able to support different freshness models (e.g., nonce vs. timestamp)

The IETF [Remote Attestation Procedures Architecture](https://github.com/ietf-rats-wg/architecture)
provides terminology and architecture for attestation procedures,
and supports the above requirements.  It is still a draft form, but
is fairly stable and while it may not be complete, the content that
is there has good consensus and is very likely to be consistent with
an eventual standard (perhaps by end of 2020?).

## User Experience

Since the architecture can be used to support many possibilities, the
use of plugins is essential.  This document does not cover how plugins
are enumerated and registered; that is left to a separate design document
that is not specific to attestation.  This document will only cover the
developer experience assuming the plugins are already available underneath
a general attestation API.

Depending on the plugin registration design, the app developer,
the enclave signer, and/or the party configuring an application will choose
one or more plugins to support and ensure they are available.

NOTE: The RATS Architecture document is maintained in the
[RATS github repository](https://github.com/ietf-rats-wg/architecture)
which may have a later version than the current Internet-Draft.  When
in doubt, go to the github repo which has links to the Internet Draft,
the latest Editors' Copy, and the diffs between them.

As noted in the
[RATS Architecture](https://github.com/ietf-rats-wg/architecture),
an implementation acts in one or more of the three roles: Attester,
Verifier, or Relying Party.  An Attester generates signed Evidence
to be processed by a Verifier.  A Verifier appraises Evidence using
an Appraisal Policy (and often Endorsements as well), and generates
Attestation Results to be processed by a Relying Party.  A Relying
Party appraises Attestation Results and typically uses them for
some authorization decision.

The APIs are thus centered around the conceptual data flow
depicted in Figure 1 in the
[RATS Architecture](https://github.com/ietf-rats-wg/architecture).

Specific formats of Evidence, Attestation Results, etc. are the
responsibility of the relevant plugins to implement, not the application.
Similarly, plugins are responsible for TEE-specific details.

The (non-attestation specific) protocol between the Attester and
a Relying Party is the responsibility of the application, not
the OE SDK or plugins.

The (attestation-specific) protocol between a Verifier and either
an Attester (in the Passport model) or a Relying Party (in the
Background-check model) is the responsibility of the relevant
plugins to implement, not the application.

It is an open question whether it is the responsibility of the app,
the OE SDK, or plugins to actually apply an appraisal policy (e.g., to do
the actual verify operation).  The appraisal policy might be hard-coded,
or be encapsulated inside endorsements, or be configured separately
through other APIs, or any combination of those.  This draft will cover
APIs that might be needed in any of these designs: appraisal in the app,
appraisal in the SDK, and appraisal in a plugin.  The open question
is which one(s) to support, and hence which subset of abstract APIs
are needed.

Note that the deprecated `oe_verify_report()` API was designed for a
combined Verifier+Relying Party, and did the appraisal underneath the
API (i.e., in the OE SDK).  However, convoluting the two roles does
not meet the more general requirements stated, and in separating them,
the open issue remains.

## Specification

The APIs below are described as _abstract_ APIs, and any concrete
APIs in C (or any other language) needs to accommodate an equivalent
set of operations and support for an (at least) equivalent set of inputs
and outputs.  This means the actual mapping of functions or arguments
need not be 1:1 as long as a mapping exists.

These APIs apply to both the "northbound" API exposed to apps by the SDK,
as well as the "southbound" API between the SDK and plugins.

### Attester APIs

#### GetEvidence call

This API is used by an app to retrieve an evidence buffer that can
be sent to a Verifier (in the Passport model), or a Relying Party
(in the Background-check model).

Inputs:

* Requested Evidence format, if any (e.g., CWT, JWT, X.509, etc.).
  Defaults to letting the plugin choose one.
* Challenge buffer OCTET STRING
* Include endorsements BOOLEAN
* Custom claims buffer OCTET STRING

Outputs:

* Evidence buffer OCTET STRING
* Format used for Evidence buffer

Return status codes:

* Success indicates that Evidence was generated as requested
* Failed-to-get-endorsements indicates that the call failed because
  "Include endorsements" was true but that endorsements could not be
  obtained
* Requested-format-not-supported indicates that the requested Evidence
  format could not be used
* Challenge-Parse-error indicates that the challenge buffer provided could not
  be correctly parsed
* Custom-Claims-Parse-error indicates that the custom claims buffer provided
  could not be correctly parsed per the requested Evidence format
* Other failure indicates that the call failed for any other reason

This is the main attestation functionality of the Attester.
The challenge buffer, which may be empty for some protocols (e.g.,
those that use timestamps and synchronized clocks to check freshness),
can be provided by the app if the app has its own way to get it
from a Verifier.  For example, in the example in Section 15.4 of
[RATS Architecture](https://github.com/ietf-rats-wg/architecture),
it is obtained via the (non-attestation specific) protocol between
the Attester and the Relying Party.  (This buffer is first created
by a Verifier in its GetChallenge call discussed below, but might be
communicated to an Attester in various ways.)

Note that Section 15.2 contains a Nonce-based Passport model example
where the challenge is obtained across the Attester-Verifier protocol,
but that protocol is the responsibility of the plugin, not the app
and so no challenge buffer needs be supplied by the app in such a model.

### Verifier APIs

#### SetEvidenceAppraisalPolicy call

This call sets an appraisal policy to be used in subsequent
AppraiseEvidence calls.

This API applies only if verification is done by a plugin or API such
as `oe_verify_report()`.  If instead verification is done by an application,
then this is the app's responsibility and this API is not needed.

If this API is needed, it is used to configure the OE SDK and/or plugin
with an appraisal policy to be used for verification. Depending on the
implementation, this policy might be persisted so it would only need to
be set at configuration time, not at verification time.

Inputs:

* Evidence appraisal policy buffer OCTET STRING
* Evidence appraisal policy buffer format

Outputs:

* Evidence appraisal policy HANDLE

Return status codes:

* Success indicates that the appraisal policy was successfully stored
  and a handle was generated
* Specified-format-not-supported indicates that the buffer format specified
  is not supported
* Parse-error indicates that the buffer provided could not be correctly
  parsed
* Other failure indicates that the call failed for any other reason

#### GetChallenge call

This call gets a buffer containing a challenge from the Verifier,
for use by an Attester when generating Evidence to be sent to
that Verifier.

Inputs: none

Outputs:

* buffer OCTET STRING

Return status codes:

* Success indicates that the output buffer contains a challenge
* Failure (if failure is possible) indicates that a challenge could not
  be generated

This call is needed, for example, by Nonce-based protocols for verifying
that Evidence generated by Attesters is fresh.  For more discussion,
see sections 9, 15.2, and 15.4 of the
[RATS Architecture](https://github.com/ietf-rats-wg/architecture).

The old OE API `oe_get_target_info_v2` would be another example of a
use case provided by this API.

#### AppraiseEvidence call

Inputs:

* Evidence appraisal policy HANDLE
* Evidence buffer OCTET STRING
* Evidence format. This may be an optional parameter if the plugin only
  supports one format, but some plugins might accept either JWT or CWT for
  instance, and supplying this avoids having to implement format detection
  heuristics by trying to parse the buffer.

Outputs:

* Claim set HANDLE

Return status codes:

* Success indicates that the Evidence was recognized as trusted
  and a Claim set handle was generated as requested
* Invalid-handle indicates that the appraisal policy handle is not valid
* Untrusted-Results indicates that the Evidence did not pass appraisal,
  but a Claim set handle was still generated.  This return status code
  only applies if appraisal is done by the plugin.  If appraisal is left
  to the app, this status code is not needed, and the API would be better
  named as ParseEvidence rather than AppraiseEvidence.
* Failed-to-get-endorsements indicates that the call failed because
  necessary endorsements could not be obtained
* Specified-format-not-supported indicates that the specified
  Evidence format is not supported
* Parse-error indicates that the Evidence buffer provided could not be
  correctly parsed
* Other failure indicates that the call failed for any other reason

This is the main attestation functionality of the Verifier.
A pure Verifier (with verification done by the SDK or a plugin) would pass
the output handle to GetAttestationResults
in order to generated signed AttestationResults.  A combined
Verifier/Relying Party could simply use it with GetClaimValue (see below).
Similarly a Verifier that does verification in the app would also use
the handle with GetClaimValue in order to retrieve values to apply the
appraisal policy to.

#### GetAttestationResults call

This API generates Attestation Results in a requested format.
If verification is done by the OE SDK and/or plugins, then
this API does so using an Evidence claim set handle.   If
verification is done by the app, then instead the claim set
handle would be a new claim set created to contain claims to appear
in the Attestation Results; the app would add claims using the
SetClaimValue API before calling GetAttestationResults to serialize
them to a given wire format.

Inputs:

* Claim set HANDLE
* Requested Attestation Results format (e.g., CWT, JWT, X.509, etc.).
  Defaults to letting the plugin choose one.

Outputs:

* Attestation Results buffer OCTET STRING
* Format used for Attestation Results buffer

Return status codes:

* Success indicates that Attestation Results were generated as requested
* Invalid-handle indicates that the claim set handle is not valid
* Requested-format-not-supported indicates that the requested
  Attestation Results format could not be used
* Other failure indicates that the call failed for any other reason

#### SetClaimValue call

This API is only needed in the northbound (i.e., app) API if verification is
done in an application.  It is needed in the southbound API if verification
is done either in the application or in the OE SDK.

Inputs:

* Claim set HANDLE
* Claim ID
* Metadata ID (defaults to none, meaning get the claim value itself).  An
  identifier of a claim about a claim, such as the timestamp at which a
  given claim value was generated, if a timestamp is included along with
  the claim.
* Value buffer OCTET STRING

Outputs: None

Return status codes:

* Success indicates that the claim value was set as requested
* Invalid-handle indicates that the claim set handle is not valid
* Other failure indicates that the call failed for any other reason

#### CreateClaimSet call

This API is only needed in the northbound (i.e., app) API if verification is
done in an application.  It is needed in the southbound API if verification
is done either in the application or in the OE SDK.

Inputs: None

Outputs:

* Claim set HANDLE

Return status codes:

* Success indicates that an empty claim set was created as requested
* Other failure indicates that the call failed for any reason

This API returns an empty claim set for use with APIs such as SetClaimValue
and GetAttestationResults.

### Relying Party APIs

#### SetAttestationResultsAppraisalPolicy call

Inputs:

* Attestation Results appraisal policy buffer OCTET STRING
* Attestation Results appraisal policy buffer format

Outputs:

* Attestation Results appraisal policy HANDLE

Return status codes:

* Success indicates that the appraisal policy was successfully stored
  and a handle was generated
* Specified-format-not-supported indicates that the buffer format specified
  is not supported
* Parse-error indicates that the buffer provided could not be correctly
  parsed
* Other failure indicates that the call failed for any other reason

This call sets an appraisal policy to be used in subsequent
AppraiseAttestationResults calls.

#### AppraiseAttestationResults call

Inputs:

* Attestation Results appraisal policy HANDLE
* Attestation Results buffer OCTET STRING
* Format used for Attestation Results buffer

Outputs:

* Claim set HANDLE

Return status codes:

* Success indicates that the Attestation Results were recognized as trusted
  and a Claim set handle was generated as requested
* Invalid-handle indicates that the appraisal policy handle is not valid
* Specified-format-not-supported indicates that the specified
  Attestation Results format is not supported
* Parse-error indicates that the Attestation Results buffer could
  not parse as a legal encoding in the specified Attestation Results format
* Unauthorized-Results indicates that the Attestation Results did not pass
  appraisal, such as coming from a Verifier that the Relying Party does not
  trust, or being past its validity period
* Other failure indicates that the call failed for any other reason

#### GetClaimValue call

Inputs:

* Claim set HANDLE
* Claim ID
* Metadata ID (defaults to none, meaning get the claim value itself).  This
  is an identifier of a claim about a claim, such as the timestamp at which a
  given claim value was generated, if a timestamp is included along with
  the claim.

Outputs:

* Value buffer OCTET STRING

Return status codes:

* Success indicates that the value buffer was generated as requested
* Invalid-handle indicates that the claim set handle is not valid
* Claim-ID-not-found indicates that no such claim is available with the
  specified ID
* Metadata-ID-not-found indicates that no such metadata is available
* Other failure indicates that the call failed for any other reason

#### EnumerateClaimIds call

This abstract API can be used to enumerate all claims in a given claim set.

Inputs:

* Claim set HANDLE

Outputs:

* List of entries where each entry has:
    * Claim ID
    * Metadata ID (defaults to none, meaning get the claim value itself)

Return status codes:

* Success indicates that the claims were enumerated
* Invalid-handle indicates that the claim set handle is not valid
* Other failure indicates that the call failed for any other reason

## Authors

Dave Thaler (dthaler@microsoft.com)
