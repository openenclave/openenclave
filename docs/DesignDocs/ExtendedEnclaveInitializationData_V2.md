Extended Enclave Initialization Data V2
=======================================

In this paper, we present an updated design of the extended enclave initialization data (EEID).

Problem Statement
-----------------

In the current design of the EEID support (URL), the variable length configuration data buffer is part of the EEID pages added into the enclave by the enclave loader, and the enclave code access the configuration data through the eeid data structure. Intel's 10th-gen Core processor supports the Key Separation and Sharing (KSS) feature, including `CONFIGID` and `CONFIGSVN`, which are new fields defined in `SECS`. `CONFIGID` is intended to allow enclave creator to indicate what additional content may be accepted by the enclave post enclave initialization, whose exact usage depends on the enclave implementation. `CONFIGSVN` can be used in case `CONFIGID` does not fully reflect the identity of the additional content that may be accepted by the enclave post enclave initialization, for example, `CONFIGID` as the hash of the signing key for verifying the additional content. The `CONFIGID` and `CONFIGSVN` are part of the enclave identity produced by the CPU, and reflects the identity of the additional code/data allowed to be loaded into the enclave, committed at the enclave initialization time. The CONFIGID/CONFIGSVN based solution on SGX CPUs would expose a API set different from the current EEID implementation.

The initial EEID design only supports enclave load time selection of heap/stack size and #TCS, and places the EEID pages after the heap and thread sections. The enclave's linear address space size is set as a fixed value big enough to encompass all reasonable selections of heap/stack size and/or #TCS, with large range of linear address potentially not committed and not accessible by the enclave code. The variance of the location of the EEID pages and the variance of the end of the committed enclave pages, both under the potentially malicious loader's control, complicate the EEID implementation and require more security design/code review and validation. For usages that do not need to support enclave load time selection of heap/stack size and #TCS, an EEID enclave with enclave heap/stack size and #TCS specified at enclave signing time is more attractive.

The update design aims to achieve the following goals:

- Unify the APIs related to manage and access the additional code/data allowed to be loaded into the enclave, between the EEID based solution and HW CONFIGID/CONFIGSVN based solution.
- Add support for EEID enclave with heap/stack size and #TCS specified at enclave signing time.
- Simplify EEID design/implementation, especially for EEID enclave with with heap/stack size and #TCS specified at enclave signing time.

Compatibility with KSS based solution
-------------------------------------

To expose the same programing interface as the future KSS based solution, the variable length configuration data is not included in the EEID page anymore. Instead, config_id and config_svn are included in the EEID page, and the size of EEID data structure is limited to 4KB to fit within one 4KB page.

The `oe_eeid_t` definition is changed from:

```C
#ifdef EXPERIMENTAL_EEID
typedef struct oe_eeid_t_
{
    uint32_t version;        /* version number of the structure */
    uint32_t hash_state[10]; /* internal state of the hash computation at the end of the enclave base image */
    uint64_t signature_size; /* size of signature */
    oe_enclave_size_settings_t size_settings; /* heap, stack and thread configuration for this instance */
    uint64_t vaddr;          /* location of the added data pages in enclave memory; EEID follows immediately thereafter */
    uint64_t entry_point;    /* entry point of the image, for SGX, matches TCS.OENTRY */
    uint64_t data_size;      /* size of application EEID */
    uint8_t data[];          /* Buffer holding EEID data followed by the signature */
} oe_eeid_t;
#endif
```

to:

```C
#ifdef EXPERIMENTAL_EEID
typedef struct oe_eeid_t_
{
    uint32_t version;        /* version number of the structure */
    uint32_t hash_state[10]; /* internal state of the hash computation at the end of the enclave base image */
    uint8_t config_id[32];   /* identity of the code/data allowed to be loaded into the enclave after enclave init */
    unit16_t config_svn;     /* minimum SVN of the code/data allowed to be loaded into the enclave after enclave init */
    oe_enclave_size_settings_t size_settings; /* heap, stack and thread configuration for this instance. if all-0, indicating heap/stack size and #TCS are specified at enclave signing time */
    uint64_t vaddr;          /* location of the EEID page in enclave memory, heap and thread sections immediately thereafter */
    uint64_t entry_point;    /* entry point of the image, for SGX, matches TCS.OENTRY */
    uint64_t signature_size; /* size of signature, max size is 4096-sizeof(oe_eeid_t) bytes */
    uint8_t signature[];     /* Buffer holding the signature */
} oe_eeid_t;
#endif
```

The enclave developer owns the definition of config_id and config_svn. The enclave developer is also responsible for the host side code that calculates the identity of the code/data to be loaded into enclave post enclave initialization and pass the proper values for config_id/config_svn to the enclave loader. The enclave loader sets the config_id/config_svn through the eeid page or in SGX `SECS` if SGX KSS is supported. The enclave developer should implement an explicit function (typically an ECALL) to load the code/data into the enclave memory post enclave initialization and to verify the identity and/or SVN of the loaded code/data against config_id/config_svn. On SGX CPUs supporting the KSS feature, config_id and config_svn are available in the SGX `REPORT`. The OE SDK libs will provide an API to retrieve config_id and config_svn. The low level implementation difference between EEID based solution and SGX KSS feature based solution is not exposed to the developer's code.

Supporting heap/stack size and #TCS specified at enclave signing time or loading time
-------------------------------------------------------------------------------------

For SGX, to simplify the design and implementation, the updated design adds a *Guard/EEID* page in the enclave memory layout between the Code and Initialized Data pages and the first heap page, for both the regular enclave and the EEID enclave.

| OE SGX Enclave Memory Layout    |
| :------------------------------ |
| Code and Initialized Data Pages |
| *Guard Page or EEID Page*       |
| Heap Pages                      |
| Guard Page                      |
| Stack pages                     |
| Guard Page                      |
| TCS Page                        |
| SSA (State Save Area) 0         |
| SSA (State Save Area) 1         |
| Guard Page                      |
| Thread local storage            |
| FS/GS Page (oe_sgx_td_t + tsp)  |
| ...                             |
| Guard Page                      |
| Stack pages                     |
| Guard Page                      |
| TCS Page                        |
| SSA (State Save Area) 0         |
| SSA (State Save Area) 1         |
| Guard Page                      |
| Thread local storage            |
| FS/GS Page (oe_sgx_td_t + tsp)  |

For a regular enclave, the enclave loader "adds" a Guard Page between the Code and Initialized Data pages and the Heap Pages (`EADD` the first heap page at the linear address = linear address of the last Code/Data page + 4KB).

For an EEID enclave, the enclave loader records the Guard Page location, adds the heap and the thread sections, and then the EEID page at the Guard Page location, as read-only. The Guard/EEID page location is fixed, as (heap_base-4KB). The EEID initialization code inside the enclave always accesses the EEID data structure at the fixed location.

For EEID enclaves with heap/stack size and #TCS specified at enclave signing time, the loader only adds one extra measured page after the original base enclave is measured by the CPU. The `hash_state` in the EEID data structure records the measurement after the heap and thread sections are added. This type of EEID enclave's SECS.Enclave_Size is determined by the base enclave.

For EEID enclaves with heap/stack size and #TCS selected by the loader at enclave loading time, the loader adds heap pages, thread sections and the EEID page after the base enclave's code and initialized data are measured by the CPU. The `hash_state` records the measurement before the heap and thread sections are added. This type of of EEID enclave's Enclave_Size in `SECS` is fixed as a large value, for example 64GB.

As discussed in the original EEID design doc(URL), an EEID enclave with heap/stack size and #TCS selected by the loader at enclave load time needs to have one thread section in the base image to capture the expected `TCS.OENTRY` value in the base enclave measurement, which does complicate the base enclave measurement recreation algorithm used in EEID enclave attestation verification. This updated design addresses the need to capture the expected `TCS.OENTRY` value in a different way.

`oe_sgx_enclave_properties` is part of the initialized data of the SGX enclave, and covered by the base enclave measurement. The enclave loader will include the expected `TCS.OENTRY` value in `oe_sgx_enclave_properties`. The definition of `oe_sgx_enclave_properties` is changed from:

```C
/* Extends oe_enclave_properties_header_t base type */
typedef struct _oe_sgx_enclave_properties
{
    /* (0) */
    oe_enclave_properties_header_t header;

    /* (32) */
    oe_sgx_enclave_config_t config;

    /* (48) */
    oe_sgx_enclave_image_info_t image_info;

    /* (96)  */
    uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];

    /* (1904) end-marker to make sure 0-filled sigstruct doesn't get omitted */
    uint64_t end_marker;
} oe_sgx_enclave_properties_t;
```

to:

```C
/* Extends oe_enclave_properties_header_t base type */
typedef struct _oe_sgx_enclave_properties
{
    /* (0) */
    oe_enclave_properties_header_t header;

    /* (32) */
    oe_sgx_enclave_config_t config;

    /* (48) */
    oe_sgx_enclave_image_info_t image_info;

    /* (96)  */
    uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];

    /* (1904) from oeimage.entry_rva, must match TCS.OENTRY */
    uint64_t entry_rva;
} oe_sgx_enclave_properties_t;
```

The EEID initialization code inside the enclave makes sure the `entry_point` in the EEID data structure matches `entry_rva` in `oe_sgx_enclave_properties`.

With this change, the base enclave of an EEID enclave with heap/stack size and #TCS selected by the loader can safely use  `NumStackPages=0`, `NumHeapPages=0`, and `NumTCS=0`. Recording the expected `TCS.OENTRY` value in `oe_sgx_enclave_properties` of a SGX enclave (regular enclave or EEID enclave) also simplifies the implementation of Enclave Dynamic Memory Management (EDMM) based thread context creation support in the future, where the enclave code needs to verify the content of a TCS page added by the OS.

Preserving base enclave properties in the signature
---------------------------------------------------

When res-signing the image using the `OE_DEBUG_SIGN_KEY`, the dynamically generated signature should preserve all relevant fields from the base enclave signature, except the enclave measurement field and the fields related to the signing operation. For SGX, the dynamically generated `SIGSTRUCT` should be identical to the base enclave `SIGSTRUCT`, except `DATE`, `MODULUS`, `SIGNATURE`, `Q1`, `Q2` (signing related) and `ENCLAVEHASH` (enclave measurement). Certain fields in SGX `SIGSTRUCT` express policies the enclave developer wants the CPU to enforce, for example, whether to prevent the initialization of the enclave if certain CPU features are enabled or disabled for the enclave. The dynamically generated `SIGSTRUCT` should not alter those policies.

Verification of EEID enclave attestation evidence
-------------------------------------------------

Verification of attestation evidence with EEID still requires a fully populated `oe_eeid_t` and it performs the following steps (not necessarily in this order):

- Create a SHA256 context and restore the internal state to `hash_state`,
- re-create the base image hash from the SHA256 context
- measure the additional pages added after the base image. For EEID enclave with the size of heap/stack and #TCS specified at enclave signing time, the only additional page is the `oe_eeid_t` page. For EEID enclave with the size of heap/stack and #TCS selected by the enclave loader at enclave loading time, the additional pages include the heap and thread sections with stack using the `size_settings` in `oe_eeid_t`. Note that the number of TCS pages determines the number of thread sections. The measurement of the heap and thread section starts at address `vaddr`+4KB and includes `entry_point` in the TCS control pages. The measurement of the eeid page at `vaddr` is added last.
- check that the final hash matches the hash reported in the extended report (e.g. MRENCLAVE),
- check the identity of the signer of the extended image (e.g. public key corresponding to `OE_DEBUG_SIGN_KEY`),
- check that the base image signature matches the ones in the extended report, except the image hash field (e.g. `sigstruct.EnclaveHash` in the case of SGX) and the signature section
- check that the base image hash matches the value in the base image signature (e.g. `sigstruct.EnclaveHash` in the case of SGX), and finally
- check the signature of the base image (e.g. `sigstruct` in the case of SGX; note this is integrity-protected by the hardware because of it's inclusion in the EEID pages).

The claims produced by the enclave attestation verification should include config_id and config_svn, as well as the base enclave's identity information from the base enclave signature. The EEID enclave attestation verification process confirms that the enclave loader follows the SW convention to add the EEID page (in EEID enclave with loader selected heap/stack size and #TCS, also the heap and thread sections) after the base image, by checking the expected measurements. So the base enclave's identity information recorded in the EEID page can be trusted to reflect the base enclave loaded.

As the enclave developer owns the definition of config_id and config_svn, the developer is responsible for providing the configuration data identified by config_id/config_svn to the Relying Party, if it's necessary for the Relying Party to analyze the configuration data. The Relaying Party should make sure the identity of the configuration data received matches config_id/config_svn claims produced by the enclave attestation verification process.

For SGX KSS feature based solution, the attestation evidence verification implementation will be different, but the claims produced will also include config_id/config_svn as well as other enclave identity information, extracted from the HW generated enclave attestation data. The low level implementation difference between EEID based solution and SGX KSS feature based solution is not exposed to the Relaying Party.
  
Authors
-------

This update to the EEID extension has been designed by Bo Zhang<zhanb@microsoft.com>.
The initial implementation has been written by Christoph Wintersteiger <cwinter@microsoft.com>
