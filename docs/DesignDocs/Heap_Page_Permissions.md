Heap Page Permissions
=====================

The permission flags on heap pages for SGX enclaves are currently hard-coded to `SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W` in [create.c](https://github.com/openenclave/openenclave/blob/43e5e1fca9a55196ac94d5079eb3e615c1b4d6e6/host/sgx/create.c#L123). Some applications, for instance SGX-LKL, require the excutable flag `SGX_SECINFO_X` as well. Given this difference in requirements, the permission flags should be a (signing-time) configuration setting, i.e. it is measured and attested.

Without a configuration setting, applications would have to modify Open Enclave (OE), which hinders interoperability with other OE applications. For example, hard-coding a modified set of permission flags means that the modified version of OE will compute different MRENCLAVEs, as the permission flags are measured during signing and enclave creation (in [sgxmeasure.c](https://github.com/openenclave/openenclave/blob/03e07014e80d4894aee58d41216eeaa6d321a11d/host/sgx/sgxmeasure.c#L92)). This makes it harder to verify that a particular measurement is correct; for instance, recomputing the MRENCLAVE from a reproducible/deterministic build of the enclave image requires the same modifications to OE. Also, if more than one image is used, they may require different versions of OE to make the measurements. In some cases, like the EEID plugin, a trivial modification of this sort means that the modified version of OE literally loses the ability to verify quotes produced with the original OE, because the verifier plugin re-measures heap pages and their flags during verification.

We propose to add a new configuration setting to `oe_enclave_size_settings_t` which tracks the permission flags:

    typedef struct _oe_enclave_size_settings
    {
        uint64_t num_heap_pages;
        uint64_t num_stack_pages;
        uint64_t num_tcs;
        uint64_t heap_permissions; /* new */
    } oe_enclave_size_settings_t;

This makes it easy to include the setting in measurements during enclave signing and creation. A copy of the `heap_permissions` is then also present in the `.oeinfo` section's `oe_enclave_properties_sgx`.

The default setting for `heap_permissions` is the current hard-coded setting, so that existing applications do not need to be modified (but perhaps recompiled and resigned).

The implementation of this feature requires trivial changes to the launcher (`create.c`) and to `oesign`, because a new setting in the configuration file parser and/or a commandline parameter are required to change the default setting.

Alternative solutions
---------------------

A new `oe_enclave_setting_type_t` could be added, which would then have to be provided to `oe_create_enclave` at signing as well as creation time. This would mean that the settings are not automatically or easily accessible later. Realistically, this solution would also have to save that information somewhere in the image, similar to saving it in the `.oeinfo` section.

In the special case of EEID, the permission flags could also be added to the EEID dynamic memory size settings, but that solves the problem only for EEID-enabled enclaves.