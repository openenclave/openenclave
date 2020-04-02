Attestation: OE SDK Integration with Intel® SGX SDK quote-ex Library for Generation of Evidence in New Formats
====

This design document proposes an extension of the OE SDK implementation
for integration with the Intel® SGX SDK quote-ex library, for support of
generation of evidence in new SGX formats such as Enhanced Privacy ID (EPID).

# Motivation

The existing implementation of OE SDK SGX attestation,
based on the Intel® SGX SDK Data Center Attestation Primitives (DCAP)
quote generation library (simply called the DCAP library),
only supports generation of evidence in a single SGX ECDSA-p256 format.

On some SGX platforms, other evidence formats, including those based on the
Enhanced Privacy ID (EPID) algorithm, are supported and preferred by
some application solutions. Generation of evidence in these formats is supported
by the Intel® SGX SDK with a library package libsgx-quote-ex
(or simply called the quote-ex library).

Note: though the acronym DCAP has "data center" in it, the DCAP library
can be used on platforms both inside and outside data centers.
Similarly, the quote-ex library can also be used on platforms both inside
and outside of data centers.

# User Experience

The proposed extension only changes the internal implementation of the OE SDK
attestation software stack. It does not impact the
[OE SDK attestation API](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/CustomAttestation_V3.md).
With the integration of the quote-ex library, an attester application enclave's
call to OE SDK API `oe_get_attester_plugins()` returns the list of all the
SGX evidence attester plugins available to the calling enclave instance.

Integration of the quote-ex library depends on the installation of the
Intel® SGX SDK quote-ex library package and its dependencies,
as well as proper configuration of the components and their access to
dependent backend services. Details for the quote-ex library installation
and configuration are outside the scope of this document.

# Specification

## Existing OE SDK Implementation

### Evidence Format Enumeration and Plugin Registration

The existing OE SDK implementation based on the DCAP library only supports
generation of evidence in a single SGX ECDSA-p256 format,
so there is no need for enumeration of supported evidence formats.
As implemented in code file `enclave/sgx/attester.c`,
a single attester plugin is created for the SGX ECDSA-p256 evidence format.

- Note: in the current OE SDK implementation, the UUID for the ECDSA-p256
evidence format is still called `OE_SGX_PLUGIN_UUID`,
which is the same as `OE_SGX_ECDSA_P256_PLUGIN_UUID`.

### Implementation of OE SDK API `oe_get_evidence()`

The current implementation of OE SDK API `oe_get_evidence()`,
in code file `common/attest_plugin.c`,
searches for an attester plugin that supports the requested evidence format,
and invokes the `get_evidence()` entry point of the selected plugin.

The SGX ECDSA-p256 attester plugin is implemented in code file
`enclave/sgx/attester.c` and other relevant enclave-side and host-side code files,
called enclave-side and host-side plugin libraries in this document.
he enclave-side plugin library interacts with the host-side plugin library
via OCALLs defined in interface definition file `common/sgx/sgx.edl`.
For SGX ECDSA-p256 evidence generation, there are 2 OCALLs:

- `oe_get_qetarget_info_ocall(sgx_target_info_t* target_info)`
    - Return the SGX Quoting Enclave (QE) target information.
- `oe_get_quote_ocall(const sgx_report_t* sgx_report, void* quote, size_t quote_size, size_t* quote_size_out)`
    - Generate an ECDSA-p256 quote and return in the caller-supplied buffer,
    or return the needed buffer size if the supplied buffer is missing or
    not large enough.

Since only a single evidence format is supported and this format does not
require any optional parameter, these OCALLs pass neither the evidence
format ID nor optional parameter.

The host-side plugin library implements the OCALLs,
as in code file `host/sgx/ocalls.c` and other relevant code files.
As defined in the main `cmake` configuration file `CMakeLists.txt`
in the OE SDK top directory, the DCAP library is linked to the OE SDK
host-side plugin library. The DCAP library provides following 3 API functions
in support of the above two OCALLs, as defined in its
[header file](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h).

- `sgx_qe_get_target_info(sgx_target_info_t *p_qe_target_info)`
    - Return the SGX Quoting Enclave (QE) target information,
    for the application enclave to generate its SGX report.
- `sgx_qe_get_quote_size(uint32_t *p_quote_size)`
    - Return the size of the buffer needed to hold the SGX ECDSA quote
    to be generated.
- `sgx_qe_get_quote(const sgx_report_t *p_app_report, uint32_t quote_size, uint8_t *p_quote)`
    - Generate an SGX ECDSA quote for the input application enclave SGX report,
    and return it in the caller-supplied buffer.

### Project Compilation and Linking

As defined in `cmake` configuration file `host/CMakeLists.txt`,
for OE SDK built on an SGX platform, the host-side plugin library code is
linked with the DCAP static library.

## Proposed Changes

### quote-ex Library API

For generation of SGX evidence in ECDSA and EPID formats, the SGX quote-ex
library has the following relevant API functions defined in its
[header file](https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_uae_quote_ex.h):

- `sgx_get_supported_att_key_ids(sgx_att_key_id_ext_t *p_att_key_id_list, uint32_t *p_att_key_id_list_size)`
    - Return the list of supported attestation key IDs (which can be mapped
    to OE SDK evidence formats) on the current platform.
    - Note: this function is not yet available in the current release,
    but will be added in a future release.
- `sgx_init_quote_ex(const sgx_att_key_id_t* p_att_key_id, sgx_target_info_t *p_qe_target_info, size_t* p_pub_key_id_size, uint8_t* p_pub_key_id);`
    - Return the SGX Quoting Enclave (QE) target information for the given
    attestation key ID.
- `sgx_get_quote_size_ex(const sgx_att_key_id_t *p_att_key_id, uint32_t* p_quote_size)`
    - Return the size of the buffer needed to hold the quote to be generated
    for the given attestation key ID.
- `sgx_get_quote_ex(const sgx_report_t *p_app_report, const sgx_att_key_id_t *p_att_key_id,sgx_qe_report_info_t *p_qe_report_info, uint8_t *p_quote, uint32_t quote_size)`
    - Generate a quote for the given attestation key ID and application
    SGX report, and return it in the caller-supplied buffer.

As compared to the DCAP library API, the quote-ex library API allows enumeration
of supported evidence formats (called attestation key IDs in the API).
Otherwise the quote-ex API is similar to the DCAP API, except that every
function takes an input attestation key ID in its parameter list.

### Host-side Plugin Library Link with the SGX DCAP and quote-ex Libraries

#### Background: the SGX DCAP and quote-ex Libraries

- The DCAP library only supports generation of SGX quotes in ECDSA-p256 format.
With DCAP, the quote generation can be done either in-process,
or out-of-process by working with a background service (called AESM) running
on the same platform.
- The quote-ex library supports generation of SGX quotes in multiple formats
(including ECDSA-p256 and EPID variations).
With quote-ex, quote generation is always done out-of-process
by working with a background service (called AESM) on the local platform.

An SGX platform can have either the quote-ex library or the DCAP library,
or both of them installed.
Installation and configuration of the AESM background service is independent
of the installation of the two libraries.

When both libraries and the background services are all installed and configured,
the quote-ex should library takes precedence, as it supports more evidence
formats.

#### Options for Host-side Plugin Library Link with the SGX DCAP and quote-ex Libraries

There are several options for the OE SDK host-side plugin library to
link with the SGX DCAP and quote-ex libraries.
Experiments in implementation will help choose the most suitable option.
In any case, from the software stack point of view,
the choice only impacts the implementation of the host-side plugin library.
It does not impact the enclave-side plugin library or the OCALL interface.

##### Option 1: Dynamic Detection and Loading of the Two Libraries

With this option, the OE SDK host-side plugin library dynamically detects
the presence of the two libraries and loads them at runtime.
If the quote-ex library is present, it loads this library and calls into it
to check if the dependent background service is available.
If so the quote-ex library is used. Otherwise the DCAP library is loaded
and used.

##### Option 2: Built-time Link with the quote-ex Library

Run-time dynamic detection and loading of multiple shared libraries
complicates implementation.
It also increases the risk of API version mismatch between OE SDK and
the loaded libraries, since the API version of the loaded libraries is not
checked at build time against library headers.

As described previously, the quote-ex library supports a superset of formats
as compared to the DCAP library, though it always depends on
a background service for quote generation.

If on SGX platforms the OE SDK always installs with the AESM background service
(as a hard dependency), then it is possible for the host-side plugin library
to be linked at build-time only with the quote-ex library. With this option,
the dependency on the DCAP library is dropped.

##### Option 3: Link with Both Libraries

To avoid the complication of dynamic library loading and to keep the flexibility
of using either one of the the libraries, the host-side plugin library can be
built to be linked to both the DCAP and the quote-ex libraries.
It first calls into the quote-ex library to check if the dependent background
service is available.
If so, the quote-ex library is used, otherwise the DCAP library is used.

### Support of SGX Evidence Formats Enumeration

The SGX plugin code file `enclave/sgx/attester.c` implements the OE SDK API
`oe_get_attester_plugins()`.
The implementation enumerates all supported SGX evidence formats,
creates a list of attester plugins for them, and returns the created list
to the caller.

For SGX evidence formats enumeration, a new OCALL is added to interface
definition file `common/sgx/sgx.edl` and implemented in the host-side
SGX plugin library:

- `oe_get_supported_attester_format_ids_ocall(void* format_ids, size_t format_ids_size, size_t* format_ids_size_out)`
    - This OCALL returns a list of supported evidence format IDs in
    caller-supplied buffer, and returns the size of the buffer actually
    used to hold the list.
    - But if the supplied buffer is missing or not large enough,
    it only returns the needed buffer size.

In the implementation of this OCALL by the host-side SGX plugin library:

- If the DCAP library is loaded, a list with a single evidence format ID for
ECDSA-p256 is returned.
- Otherwise if the quote-ex library is loaded, its API
`sgx_get_supported_att_key_ids()` is invoked, and the returned list of
attestation key IDs is converted to a list of OE SDK evidence format IDs.

### Updated Implementation of SGX Plugin Function get_evidence()

The OCALLs for SGX evidence generation are extended to include the requested
evidence format ID and its companion optional parameters, as shown below:

- `oe_get_qetarget_info_ocall(const oe_uuid_t* format_id, const void* opt_params, size_t opt_params_size, sgx_target_info_t* target_info)`
    - Return the SGX Quoting Enclave (QE) target information for the given
    evidence format ID and its optional parameters.
- `oe_get_quote_ocall(const oe_uuid_t* format_id, const void* opt_params, size_t opt_params_size, const sgx_report_t* sgx_report, void* quote, size_t quote_size, size_t* quote_size_out)`
    - Generate a quote for the given evidence format ID and its optional
    parameters, and return it in the caller-supplied buffer.
    - But if the supplied buffer is missing or not large enough,
    only the needed buffer size is returned.

In the host-side SGX plugin library implementation:

- If the DCAP library is loaded, only evidence format of ECDSA-p256 is accepted,
and the corresponding DCAP API entry point functions are invoked to get the
QE target info or to generate the quote.
- If the quote-ex library is loaded, the host-side library maps the input
evidence format ID to the corresponding SGX attestation key ID and applies
the optional parameter to the key ID structure (if any), and invokes the
quote-ex API entry point functions to get the QE target info or to generate
the quote.

# Alternates

The SGX quote-ex library is the only option available to support SGX evidence
formats other than ECDSA-p256.

# Authors

- Name: Shanwei Cen
    - email: shanwei.cen@intel.com
    - github user name: shnwc
- Name: Yen Lee
    - email: yenlee@microsoft.com
    - github username: yentsanglee
