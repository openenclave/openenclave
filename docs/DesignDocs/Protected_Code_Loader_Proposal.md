Open Enclave Protected Code Loader
====

Enabling Enclave Code Confidentiality in Open Enclave.

# Motivation
Current Open Enclave SDK provides code integrity and data confidentiality at
run-time but not enclave binary confidentiality on a disk. The enclave binary
is in plaintext and can be reverse engineered to reveal code logic and
secret data embedded in the enclave image. 

The Open Enclave Protected Code Loader enables providing confidentiality 
and integrity to the IP sections in the enclave image based on ELF format.

The solution provided here is for enclaves built by statically linked libraries
in OpenEnclave SDK. This is a parity of Protected Code Loader in Intel's SGX SDK.

# User Experience
## Enclave Build-time:
### Linking pcl lib to the enclave 
On building the enclave, a static lib "liboepcl.a" should be linked to the 
enclave image with the compilation option "-Wl, whole-archive", the compiler 
option is used to force the section ".pcltbl" included in the enclave image. 
### Encrypt the enclave image
An encryption tool is provided as a pre-step to the enclave signing process:

```bash
oeencrypt -i my_enclave -o my_enclave.enc -k keyfile
```

## Enclave Initialization and Decryption
After enclave loaded, on its initialization, it will be decrypted inside the 
trusted environment, this step is done by the OE SDK runtime and invisible 
to users.

# Specification

## Protected Code Loader Software Work Flow in Open Enclave
### Build time encryption 
    A seperate tool "oeencrypt" is provided at enclave build time to encrypt 
    the enclave image right before the enclave signing process.  
### Enclave Initialization Time Decryption
    On enclave initialization operation (EINIT operation), right before relocation, 
    the encrypted enclave image needs to be decrypted and then perform the relocation
    operation.


## Encryption Algorithm in Protected Code Loader
Using openssl AES-256-GCM as the encryption/decryption algorithm.

## ELF Sections Left Plaintext
### PCL table entry 
A PCL table entry (a section called ".pcltbl" in ELF file)is built into the Enclave 
image by linking to PCL lib, i.e. liboepcl.a, this part contains enclave decryption
info on enclave loading and must remain plaintext.

Definition of PCL entry(section ".pcltbl"):
```
typedef struct pcl_table_t_
{
	/* Current state of PCL: initailized to PCL_PLAIN */
    pcl_status_e pcl_state;                   
    uint32_t     reserved1[3];                /* Must be 0 */
	// GUID must match GUID in Sealed blob
    uint8_t      pcl_guid[PCL_GUID_SIZE]; 
    size_t       sealed_blob_size;            
    uint32_t     reserved2[2];                /* Must be 0 */
	/* For security, sealed blob is copied into enclave */
    uint8_t      sealed_blob[PCL_SEALED_BLOB_SIZE];
	/* SHA256 digest of decryption key */
    uint8_t      decryption_key_hash[SHA256_HASH_SIZE];
	/* Number of RVAs */
    uint32_t     num_rvas;                    
    uint32_t     reserved3[3];                /* Must be 0 */
	/* Array of rva_size_tag_iv_t */
    rva_size_tag_iv_t rvas_sizes_tags_ivs[PCL_MAX_NUM_ENCRYPTED_SECTIONS]; 
}pcl_table_t;
```

### Sections Left Plaintext
1. ELF header - binary header
2. Sections table
3. Segments table
4. Sections' names string table pointed by e_shstrndx (e.g. .shstrtab)
5. .oeinfo section holds enclave's metadata (properties)
6. .bss and .tbss
7. sections required to construct dyn_info (.dynamic)
8. sections holds the content provided by entries with index DT_SYMTAB, DT_STRTAB and DT_REL in
   dyn_info (e.g. .dynsym, .dynstr, .rela.dyn)
9. sections containing PCL code and data:
   a. section ".pcltbl"  // Designated section for PCL table
   b. .nipx, .nipd, .niprod, .nipd_rel, .nipd_rel_ro_local
10. sections for debugging
   .comment, .debug_abbrev, .debug_aranges, .debug_info, .debug_line, .debug_lc, .debug_ranges,
   .debug_str

## Elf Sections to Be Encrypted
Sections not mentioned above are sections containing IP information that need to be protected.
Mainly those sections are:
1. Code sections -- .text in elf file
2. Data sections -- .data in elf file (initialized local/global variables)
3. Read-only Data sections -- .rodata in elf file (const variables)
4. sections containing relocation info related with the above items

## Provisioning Enclave for the Encryption Key
The ISV must produce a seperate enclave to provision the system with a sealed encryption/
decryption key. The key could be obtained via Remote Attestation and then seal it to MRSIGNER
and the platform as a "sealed_blob". 

The "sealed_blob" is passed in enclave setting in oe_create_enclave for decryption encrypted 
IP sections inside enclave.

## new APIs and Libraries
### Encryption Tool -- oeencrypt
- New tool for ELF image encryption --- oeencrypt: placed in OESDK installation folder as the bin files.
- New library for section ".pcltbl" and decryption --- liboepcl.a: placed in OESDK installation folder
as the lib files

### Modifications to OE SDK Runtime Library
No new APIs exposed to user.
1. A new setting is defined in include/openenclave/host.h as the argument to support
protected code loader enclave loading in API oe_create_enclave.
```
typedef enum _oe_enclave_setting_type
{
	// PCL setting type
	OE_ENCLAVE_SETTING_PCL = 0xac120002,
	...
} oe_enclave_setting_type_t;

typedef struct _oe_enclave_setting
{
    oe_enclave_setting_type_t setting_type;
    /**
     * The specific setting for the enclave, such as for configuring
     * context-switchless calls.
     */
    union {
		/* for protected code loader */
		uint8_t* sealed_blob;
	} u;
} oe_enclave_setting_t;
```

2. uint8_t *sealed_blob is defined as new member for each instance oe_enclave_t.
3. oe_enclave_ecall_ms_t in bits/sgx/sgxtypes.h is defined as the arg_in of ecall on the 1st time
of initializing an encrypted enclave.

```
	typedef struct _oe_sgx_ecall_ms
	{
		uint64_t arg1;
		uint64_t sealed_blob;
	} oe_sgx_ecall_ms_t;
```

4. new lib for section ".pcltbl" and decryption -- liboepcl.a: placed in OESDK installation lib folder

### PCL Sample Code
A Sample Code project will be provided in samples for how to use Protected Code Loader.

## Debugging Consideration When User Launches an Encrypted Enclave
Debugging with oegdb should work regularly with a minor disclaimer: you can insert break points in
the IP code but these breakpoints in IP code must be disabled while the Protected Code Loader is
running.
Problem description: When User adds a breakpoint oegdb modifies the code, if modification is
inside the cipher-text binary then when AES-GCM is applied the tag result will not match.

After PCL flow is done, breakpoints can be added and debuuging can continue regularly.

Solution: ISV should be able to choose when host attaches the debugger:
1. Default: debugger shall be attached after PCL flow is done.
2. For PCL and early trusted runtime development: debugger shall be attached before the first
instruction inside an enclave

# Alternative Architecture
Current PCL architecture only supports section based encryption to ELFs with static link libraries.

But if user wants to use dynamic linking for enclaves, there are one alternative:
1. Encryption entire DSO(for algorithms, e.g.) linked to the enclave
2. Designate a special DSO for pcl decryption if user wants to use dynamic link for the enclave
3. Requires a dynamic linker within the enclave

# References
https://download.01.org/intel-sgx/sgx-linux/2.11/docs/Intel_SGX_Developer_Reference_Linux_2.11_Open_Source.pdf

# Authors

- Xiangping Ji (@jixiangp)
