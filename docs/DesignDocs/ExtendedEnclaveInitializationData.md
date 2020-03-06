Extended Enclave Initialization Data
=====

We present an extension of Intel SGX attestation in OpenEnclave that enables the attestation of enclave initialization parameters.
Our extension uses MRENCLAVE as a platform configuration register to measure additional data besides the signed enclave image, such as instance-specific enclave configuration and the settings in the current enclave signing configuration.

We introduce a new OE quote type for SGX quotes with extended enclave initialization data (EEID).
Recipients of such quotes must be able to recover and verify the original enclave identity information (including the original MRENCLAVE and MRSIGNER of the base image), based on the knowledge of the initialization data, which is transmitted alongside the quote as a new collateral type.


Motivations
----------

With current SGX quotes, applications can attest their configuration as part of the `reportData` argument of `oe_get_report`.
This mechanism works robustly when the application code is entirely and statically known to the validator of the quote.

Things get more complicated if an enclave executes user code that is not part of the signed enclave image. For instance, consider an enclave containing a JavaScript interpreter that executes user scripts from the host and has access to the `oe_get_report` API. It is impossible to know which script has been executed by such an enclave based on a standard quote, even if the hash of the script is included in the `reportData`, because a malicious script can obtain a valid quote with `oe_get_report` pretending to be a honest script. Similarly, if an enclave loads and execute arbitrary assembly code from the host, this assembly code can use the `EGETQUOTE` instruction to create valid reports - hence, it is impossible to use attestation to tell which assembly code has been loaded by the enclave.

An important instance of this problem is Azure Confidential Containers: the base enclave image contains the SGX-LKL runtime, which executes a user container. The container contains arbitrary code, which can use the `EGETQUOTE` instruction to obtain a valid quote for arbitrary `reportData` – potentially impersonating other containers.

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

![Design Overview](eeid.png "EEID Design Overview")

The changes introduced by EEID are mostly internal to the enclave initialization function (`oe_create_enclave_eeid`) and the attestation functions (`oe_get_report`/`oe_verify_report`).

First, before an enclave image with EEID is loaded, we patch the size settings from the signed image with the instance-specific settings.
This actually alters the computation of the `MRENCLAVE` as the sequence of calls to `EADD/EEXTEND` is modified compared to the values used during signing.
```C
    if (eeid)
    {
        if (props.header.size_settings.num_heap_pages != 0 ||
            props.header.size_settings.num_stack_pages != 0 ||
            props.header.size_settings.num_tcs != 0)
            OE_RAISE(OE_INVALID_PARAMETER);

        props.header.size_settings.num_heap_pages =
            eeid->size_settings.num_heap_pages;
        props.header.size_settings.num_stack_pages =
            eeid->size_settings.num_stack_pages;
        props.header.size_settings.num_tcs = eeid->size_settings.num_tcs;

        // patch
        elf64_sym_t sym_props = {0};
        const elf64_t* eimg = &oeimage.u.elf.elf;
        if (elf64_find_symbol_by_name(
                eimg, "oe_enclave_properties_sgx", &sym_props) == 0)
        {
            uint64_t* sym_props_addr = NULL;
            sym_props_addr =
                (uint64_t*)(oeimage.image_base + sym_props.st_value);
            oe_sgx_enclave_properties_t* p =
                (oe_sgx_enclave_properties_t*)sym_props_addr;
            p->header.size_settings = props.header.size_settings;
        }
    }
```

Then, after the enclave image is loaded but before it is initialized, we add the additional memory pages containing the contents of the `oe_eeid_t` struct:

```C
        oe_sha256_context_t* hctx = &context->hash_context;
        sgx_sigstruct_t* sigstruct = (sgx_sigstruct_t*)properties->sigstruct;
        memcpy(eeid->sigstruct, (uint8_t*)sigstruct, sizeof(sgx_sigstruct_t));
        oe_sha256_save(hctx, eeid->hash_state_H, eeid->hash_state_N);
        eeid->data_vaddr = *vaddr;

        uint64_t ee_sz = sizeof(oe_eeid_t) + eeid->data_size;
        uint64_t epg_sz = eeid_pages_size(eeid);
        uint64_t num_pages = epg_sz / OE_PAGE_SIZE;
        assert(*vaddr == enclave_end - epg_sz);

        oe_page_t* pages = (oe_page_t*)eeid;
        if (ee_sz < epg_sz)
        {
            oe_page_t* tmp = (oe_page_t*)calloc(1, epg_sz);
            memcpy(tmp, eeid, ee_sz);
            pages = tmp;
        }

        OE_CHECK(_add_extra_data_pages(
            context, enclave->addr, pages, num_pages, vaddr));

        if (ee_sz < epg_sz)
            free(pages);

        OE_SHA256 ext_mrenclave;
        oe_sha256_final(hctx, &ext_mrenclave);
```

Finally, since the changes invalidate the signature of the base image, we need to dynamically re-sign the enclave. For this, we use the `OE_DEBUG_SIGN_KEY`, which is well-known by all OE users. Note that applications should never rely on the apparent `MRSIGNER` of an EEID quote. Indeed, what we reflect to the application when we validate an EEID quote is the `MRSIGNER` of the base image.

```C
        OE_CHECK(oe_sgx_sign_enclave(
            &ext_mrenclave,
            properties->config.attributes,
            properties->config.product_id,
            properties->config.security_version,
            OE_DEBUG_SIGN_KEY,
            OE_DEBUG_SIGN_KEY_SIZE,
            sigstruct));
```

The changes to enclave initialization must be reflected for the validation of EEID quotes.
We also introduce a serialization function `oe_serialize_eeid` for the `oe_eeid_t`, as it is required by the verifier to re-compute and validate both the `MRENCLAVE` and `MRSIGNER` of the base image, based on the configuration of the instance.


Authors
-------

This extension has been designed by Antoine Delignat-Lavaud <antdl@microsoft.com> and Sylvan Clebsch <syclebsc@microsoft.com>, with inputs from Pushkar Chitnis <pushkarc@microsoft.com>.
The initial implementation has been written by Christoph Wintersteiger <cwinter@microsoft.com>
