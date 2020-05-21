# OP-TEE Integration

## Terminology

* REE: Rich Execution Environment (i.e., the untrusted OS)
* Trusted Application (TA): OP-TEE's term for an enclave
* Client Application (CA): OP-TEE's term for a host application

### Pseudo-TAs

Separate from TAs, OP-TEE also has the concept of a "Pseudo-TA (PTA)" which
is a _kernel-mode_ extension of OP-TEE whose interface boundaries are the
same as those of a regular (i.e., user-mode) TA.
The Open Enclave SDK cannot currently be used to write
Pseudo-TAs since they are kernel-mode extensions baked into OP-TEE itself,
whereas the Open Enclave SDK
is designed for developing user-mode apps that can be unloaded at runtime.

## Design Notes

### Enclave Load Procedure

A CA sends a request to OP-TEE to open a session against a TA by UUID. As
a result, OP-TEE iterates over its TA stores. A TA store abstracts the
underlying storage providers for TA binaries. OP-TEE has three TA stores:
the REE TA store, the Secure TA store, and the Early TA store.

The Early TA store loops over TA binaries baked into the OP-TEE image
itself, by UUID. The Secure TA store loops over TA binaries stored on an
RPMB (Replay-Protected Memory Block) device, again by UUID. The REE TA
store loops over TA binaries stored on the REE's filesystem, also by UUID,
with the help of a non-secure user-mode daemon (the TEE supplicant).

Since the RPMB device is assumed to be secure (data on it is encrypted,
and OP-TEE and it communicate over a secure channel) and that TA binaries
baked into OP-TEE are as secure as OP-TEE itself, they are effectively
stored in cleartext as far as reading them is concerned.

The REE TA store on the other hand requires that TA binaries have an
additional header (see section 2.10.3 of
the [OP-TEE documentation](https://optee.readthedocs.io/_/downloads/en/latest/pdf/))
tacked to the top that includes its signature and encryption information,
if applicable. The format of this header is defined by OP-TEE, not mandated
by GlobalPlatform. A TA binary in the REE TA store thus looks like:
```
 Bin Hdr | ELF ( TA Hdr (.ta_info section) | .text | .bss | etc. )
```
As a result, one cannot load the resulting .ta file as a standard ELF binary
unless one knows to skip past the TA binary header.
For OP-TEE 3.6.0 (which the Open Enclave SDK currently uses), the TA binary
header is in fact composed of several structures.

First, there is the signed header (`shdr`): it contains a magic value [u32],
the image type (i.e., Bootstrap TA or Encrypted TA) [u32], the image size
(i.e., the size of the standard ELF binary [u32], the ID according to
GlobalPlatform of the algorithm used to compute the TA's signature [u32],
the length in bytes of the hash of some of the headers and the image [u16],
the size of the signature of said hash [u16], the hash itself [u8[]], and
the signature of the hash [u8[]].

Second, there is the bootstrap TA header (`shdr_bootstrap_ta`): it contains
the UUID of the TA [u8[]], and the TA version (used for rollback protection)
[u32].

Third, there is the encryption header (`shdr_encrypted_ta`): it contains the
ID according to GlobalPlatform of the encryption algorithm [u32], the flags
for said algorithm [u32], the size of its IV [u16], the size of its
auth. tag [u16], the IV [u8[]], and the auth. tag [u8[]].

```
struct shdr {
  uint32_t magic;
  uint32_t img_type;
  uint32_t img_size;
  uint32_t algo;
  uint16_t hash_size;
  uint16_t sig_size;

  /*
   * Dynamically-sized arrays:
   *
   * uint8_t hash[hash_size];
   * uint8_t sig[sig_size];
   */
};

struct shdr_bootstrap_ta {
  uint8_t uuid[sizeof(TEE_UUID)];
  uint32_t ta_version;
};

struct shdr_encrypted_ta {
  uint32_t enc_algo;
  uint32_t flags;
  uint16_t iv_size;
  uint16_t tag_size;

  /*
   * Dynamically-sized arrays:
   *
   * uint8_t iv[iv_size];
   * uint8_t tag[tag_size];
   */
};
```

Encrypting TAs is optional.
For an encrypted TA, the hash is computed as follows:
```
H = SHA_256(shdr | shdr_bootstrap_ta | shdr_encrypted_ta | standard ELF)
```

For a cleartext TA, the hash is computed as follows:
```
H = SHA_256(shdr | shdr_bootstrap_ta | standard ELF)
```

The signature is computed as follows:
```
S = RSA_SSA_PKCS1_PSS_MGF1_SHA256(H)
```

The ciphertext is computed as follows:
```
C = AES_GCM(standard ELF)
```

For an encrypted TA, the final TA image is composed as follows:
```
TA = (shdr | H | S | shdr_bootstrap_ta | shdr_encrypted_ta | C)
```

For a cleartext TA, the final TA image is composed as follows:
```
TA = (shdr | H | S | shdr_bootstrap_ta | standard ELF)
```

For OP-TEE 3.6.0, `shdr_encrypted_ta` does not exist and there only exists
the Bootstrap TA image type.

When OP-TEE reads a TA binary
from the REE TA store, the store takes care of performing signature
verification and decryption.

In this document, we refer to the component that lays out ELF sections
onto secure-world memory as the "TA loader proper", to distinguish it
from the REE TA Store that loads a binary from the non-secure filesystem.
The TA loader proper goes through the binary and readies it in secure
memory for execution.

By the time a TA binary reaches the TA loader proper, if the binary was loaded from
the REE TA store, the TA binary header has already been stripped away
and the entire binary is in cleartext. If the binary was loaded from
either of the other two stores, the TA binary header will already never
have been there to begin with.

After the TA loader lays out the binary in memory and has had the TA
instance initialize itself, a session handle is returned to the CA. This
session handle is then used by the CA for subsequent communication with
the TA instance.

#### Image Validation

When a TA is read from the REE's filesystem, the REE TA store checks that
the signature of the hash is correct. Then, it computes the hash as per the
formulas above, choosing which one depending on whether the TA is encrypted,
and verifies that it matches the signed hash. If everything checks out, the
cleartext, standard ELF binary is passed to the TA loader proper.

#### TA Stores & Open Enclave

A TA is a TA regardless of where it is stored. The three TA stores, namely
the REE TA store, the Secure Storage TA store, and the Early TA store,
retrieve regular TA binaries. So, if you build a TA with the Open Enclave SDK,
you can make that into an early TA by feeding it to OP-TEE's build system,
which will embed the TA binary into OP-TEE itself. Similarly, you can take
an Open Enclave TA and install it into secure storage.

There is a Pseudo-TA called the Secure Storage Management
PTA (henceforth, secstor PTA). The secstor PTA exposes an install command to
the non-secure world. This commands takes a TA binary that sits in the REE's
filesystem, performs the same validation steps as the REE TA store on the
TA binary header (except that encrypted TAs cannot be installed), and if it
all checks out, the cleartext, standard ELF is written out to secure storage
(either to the RPMB, or to an encrypted blob on the REE's filesystem for
which only OP-TEE has the key).

### TA Metadata

The metadata for an enclave is split between the TA binary header, the TA
header, and global variables. The first was discussed above and said to be
consumed exclusively by the REE TA store.

The TA header includes the UUID of the TA, the requested stack size, and flags
that describe the desired runtime behaviour of the TA (see section 2.10.5 in
the [OP-TEE documentation](https://optee.readthedocs.io/_/downloads/en/latest/pdf/)).
The TA header is placed in an ELF section named `.ta_head` and is explicitly
located at the top of the resulting ELF binary via a linker script. The TA
header is only used at load time.

The primary global variable, `ta_props`, is used by libutee. libutee is the
secure user-mode library that implements the
[GlobalPlatform TEE Internal Core API](https://globalplatform.org/specs-library/tee-internal-core-api-specification-v1-2/)
for OP-TEE.

Just like Open Enclave has host-side APIs and enclave-side
APIs, so too does GlobalPlatform: the GlobalPlatform TEE Client API is
host-side and the GlobalPlatform TEE Internal Core API is enclave-side.
Thus, the OpenEnclave host-side APIs are implemented on top of the
GlobalPlatform TEE Client API, and the OpenEnclave enclave-side APIs
are implemented on top of the GlobalPlatform TEE Internal Core API.

The libutee API contains property retrieval functions (see section 4.4 of that spec), among
others. These property retrieval functions are implemented by libutee and
read `ta_props`.  `ta_props` is not used for anything else, and its contents
do not affect the runtime behavior of the TA.

There is another global variable named `__ftrace_info` which, when defined,
is used by the TA loader to initialize FTRACE support.

oeenclave for OP-TEE has a public link dependency against libutee (named
`oeutee` in the build system). Hence, all Open Enclave enclaves for OP-TEE
link against it, too. The enclave component of the SDK is shimmed atop libutee.

#### Influence on Attestation

OP-TEE provides no attestation primitives, only secure storage services for
keys and blobs (see section 2.9 in the
[OP-TEE documentation](https://optee.readthedocs.io/_/downloads/en/latest/pdf/)).

The attestation mechanism that was designed for OP-TEE is based on the
Trusted Computing Group (TCG)'s DICE with certificates.

The measurement of a TA binary influences its identity in this system. By
virtue of the TA binary header, the TA header, and the global variables
being part of the resulting TA binary, it follows that they become part of
the latter's measurement, and thus affect its keys.

### Launch Modes

There is currently no software debugging mechanism available in OP-TEE.
The way `oe_create_enclave` is currently implemented for OP-TEE
is such that if the developer specifies DEBUG, SIMULATE must also be specified.
This matches the expected usage of an ARM TrustZone emulator to debug a TA.

### Enclave Loader

#### Versioning

OP-TEE does not provide a mechanism for TA binaries to indicate what version
of the TA loader they were built for. There is an entry in the TA binary
header that specifies whether a TA is a legacy TA, a bootstrap TA, or an
encrypted TA, but this information does not make it to the TA loader; it
is consumed by the REE TA store.

However, OP-TEE does implement two TA load behaviors, seeing as an improvement
was made to the layout of TA binaries to avoid having to mark read-only
sections as read-write and storing the TA entry point in the TA header.

To determine which load path to take, the TA loader uses a heuristic based
on the `entry` field of the `ta_head` structure. If it is `UINT64_MAX`, the
TA is assumed to be in the new format (and the name of that field is
`depr_entry`); if it is not, it is presumed to be in the old format. The old
format is referred to as "Legacy TA" and the new format as "Bootstrap TA".

One may conclude from this that there is no formal method for a TA binary to
express which version of the TA loader it was built for.

### TA Signing

The signing and optional encryption mechanism is described (rather briefly)
in section 2.10.2 of the
[OP-TEE documentation](https://optee.readthedocs.io/_/downloads/en/latest/pdf/)).
The format is made quite clear by reading the
[signature script](https://github.com/OP-TEE/optee_os/blob/3.6.0/scripts/sign.py) and
[encryption script](https://github.com/OP-TEE/optee_os/blob/master/scripts/sign_encrypt.py).
Note that TA encryption was added post-OP-TEE 3.6.0. As such, this feature
is not yet supported by Open Enclave, which is based on OP-TEE 3.6.0.

#### TA Loader & Signing

The verification of a TA's signature and its decryption are not performed by
the TA loader. Rather, they are performed by the REE TA store. The REE TA
store takes care of implementing the support for signature validation and
decryption. By the time the TA binary reaches the TA loader, it is in
cleartext and the signature and encryption header has been discarded.

#### Custom Store / Loader

It would be possible to create a new TA store that implements Open Enclave
style metadata support, though that would require an Open Enclave specific
change to OP-TEE itself.  However, that would probably not be sufficient.
For example, if we must standardize on how to represent the required stack
size for an enclave, that would require a change in the TA loader as well
unless we standardize on the representation already used by OP-TEE.
Hence, a new TA store or modification of the current one as well as changes
to the TA loader might be required.

#### Convergence

Issue #2041 tracks the fact that `oesign` is SGX-specific and that signing
OP-TEE TAs is completely different. While one could rewrite OP-TEE's signature
script in C, it would seem preferable to invoke it from oesign. The reason is
that the script may change from release to release and is thus a moving
target. If we were to converge on a single metadata format, then the problem
would of course go away.

With regards to backwards compatibility in the metadata, OP-TEE follows
GlobalPlatform's specification. GlobalPlatform explicitly calls out backwards
compatibility in its specs, so there should be no breaking changes regarding
the properties (i.e., `ta_props`).

Regarding the TA binary and TA headers, which are not specified by
GlobalPlatform, there is no specific call-out for backwards compatibility.
However, OP-TEE continues to ensure that TAs built for old versions don't
break when run on newer versions. The
notion of legacy TAs vs bootstrap TAs is an example of this.

It would nevertheless perhaps be preferable to explicitly version metadata
across the board, though that would again require changing OP-TEE.

### Enclave Signing Procedure

sign.py and the key baked into OP-TEE, among other artifacts, are exported
to the TA Dev Kit during OP-TEE's build process. The SDK uses the
`OE_TA_DEV_KIT_DIR` CMake
parameter at build-time that specifies where the TA Dev Kit lives against
which the SDK must be built. The `add_enclave` CMake function picks up
`sign.py` and the TA signing key from the TA Dev Kit and applies it to every
TA built.

For users who consume the SDK in binary form, the onus is currently on them
to replicate these steps, which is why the samples aren't yet ready for
OP-TEE. The same is true for SGX, where the signature steps are duplicated
in the samples' Makefiles and CMakeLists.txt files.
Thus, the build steps currently only generate properly signed SGX enclaves,
and not OP-TEE TAs.  One possible future direction would be to export the
`add_enclave` function from the build system, so this signing logic
wouldn't have to be copied around by developers consuming the CMake exports
from a binary release.
