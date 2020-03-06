Extended Enclave Initialization Data
=====

We present an extension of Intel SGX attestation in OpenEnclave that enables the attestation of enclave initialization parameters.
Our extension uses MRENCLAVE as a platform configuration register to measure additional data besides the signed enclave image, such as instance-specific enclave configuration and the settings in the current enclave signing configuration.
We introduce a new OE quote type for SGX quotes with extended enclave initialization data (EEID).
Recipients of such quotes must be able to recover and verify the original enclave identity information (including the original MRENCLAVE and MRSIGNER of the base image), based on the knowledge of the initialization data, which is transmitted alongside the quote as a new collateral type.


Motivations
----------

With current SGX quotes, applications can attest their configuration as part of the `user_data` argument of `oe_get_report`.
This mechanism works robustly when the application code is entirely and statically known to the validator of the quote.

Things get more complicated if an enclave executes user code that is not part of the signed enclave image. For instance, consider an enclave containing a JavaScript interpreter that executes user scripts from the host and has access to the `oe_get_report` API. It is impossible to know which script has been executed by such an enclave based on a standard quote, even if the hash of the script is included in the `user_data`, because a malicious script can obtain a valid quote with `oe_get_report` pretending to be a honest script. Similarly, if an enclave loads and execute arbitrary assembly code from the host, this assembly code can use the `EGETQUOTE` instruction to create valid reports - hence, it is impossible to use attestation to tell which assembly code has been loaded by the enclave.

An important instance of this problem is Azure Confidential Containers: the base enclave image contains the SGX-LKL runtime, which executes a user container. The container contains arbitrary code, which can use the `EGETQUOTE` instruction to obtain a valid quote for arbitrary `user_data` – potentially impersonating other containers.

One way to solve this issue is to re-compile and re-sign a new enclave image for every container we execute (with the container data being measured together with the LKL base). However, this approach is cumbersome as we would like to be able to launch arbitrary containers on-demand without having to build and sign a new enclave image every time.

Another class of problems we address is dynamic attestation of the memory and thread configuration. In current OE attestation, these settings (`NumStackPage`, `NumHeapPages`, `NumTCS`) are part of the configuration to sign an enclave. This means that it is not possible to deploy the same enclave image with different memory and core configurations.

User Experience
---------------

The user decides to enable the use of EEID when the enclave base image is signed: we require that EEID enclaves use `NumStackPages=0`, `NumHeapPages=0`, and `NumTCS=0`.
This guarantees that enclave images meant to be used with EEID cannot be accidentally initialized with normal attestation (the enclave will fail to load).

To launch an EEID enclave, the user needs to use the new `oe_create_enclave_eeid` API:
```C
oe_result_t oe_create_enclave_eeid(
    const char* enclave_path,
    oe_enclave_type_t enclave_type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_count,
    oe_eeid_t* eeid,
    oe_enclave_t** enclave_out)
```

The additional input to start an EEID enclave contains the following information:

```C
typedef struct oe_eeid_t_
{
    uint32_t hash_state[10]; /* internal state of the hash at the end of the enclave base image */
    uint8_t sigstruct[1808]; /* complete sigstruct computed for the base image */
    oe_enclave_size_settings_t size_settings; /* heap, stack and thread configuration for this instance */
    uint64_t data_size;  /* size of application EEID */
    uint64_t data_vaddr; /* location of application EEID */
    uint8_t data[];      /* actual application EEID */
} oe_eeid_t;
```

Once an enclave has been started with EEID, it can use `oe_get_report` as usual to create quotes. The quote will not be verifiable by enclaves built with the Intel SDK.
However, enclaves built with OE can validate the report with `oe_verify_report` as usual, regardless of whether they themselve use EEID, as long as their version of OE supports EEID.

Specification
-------------




Authors
-------

This extension has been designed by Antoine Delignat-Lavaud <antdl@microsoft.com> and Sylvan Clebsch <syclebsc@microsoft.com>, with inputs from Pushkar Chitnis <pushkarc@microsoft.com>.
The initial implementation has been written by Christoph Wintersteiger <cwinter@microsoft.com>
