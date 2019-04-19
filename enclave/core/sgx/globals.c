// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/posix/uid.h>

/* Note: The variables below are initialized during enclave loading */

extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;

void* memcpy(void*, const void*, size_t);

#if defined(__linux__)
/**
 *****************************************************************************
 * Global variables and RIP-relative addressing

 * In linux, by default all symbols are exported. The compiler makes a
 * distinction between the following 3 kinds of global variables when
 * generating position-independent-code (via -fPIC or -fpic):
 *     1. static global:
 *           static int g1;
 *           int get_g1() { return g1; }
 *
 *        The compiler always generates RIP relative addressing for static
 *        global variables since it knows that these variables cannot be
 *        accessed by other compilation units:
 *
 *           get_g1:
 *              movl g1(%rip), %eax
 *              ret
 *
 *        Note: With optimizations enabled, the compiler can completely
 *        get rid of these static global variables if their values don't
 *        seem to be changed within the compilation unit.
 *
 *     2. Local global:
 *           int g2;
 *           int get_g2() { return g2; }
 *
 *        Local globals are defined in the current compilation unit.
 *        However another compilation unit can refer to this global via an
 *        external declaration. Therefore the compiler adds an entry for
 *        the variable in the Global Offset Table (GOT) and uses double
 *        indirection to access the variable:
 *
 *           get_g2:
 *              movq g2@GOTPCREL(%rip), %rax
 *              movl (%rax), %eax
 *              ret
 *
 *        Even though the compiler knows that the current compilation unit
 *        defines the variable, another definition of the variable could
 *        already have been loaded into memory at runtime (in another
 *        shared-library that has a variable of the same name), hence
 *        the compiler conservatively uses RIP-relative addressing even
 *        in the current compilation unit.
 *
 *     3. extern global:
 *           extern int g3;
 *           int get_g3() { return g3; }
 *
 *        These are global variables defined in another compilation unit and
 *        the addresses of these variable can only be known at run time.
 *        Therefore the compiler always generates an entry in the GOT for
 *        these variables.
 *
 *           get_g3:
 *              movq g3@GOTPCREL(%rip), %rax
 *              movl (%rax), %eax
 *              ret*
 *
 * Note, if the source code is compiled using position independent executable
 * flags (-fPIE or -fpie) instead of position independent code flags
 * (-fPIC or -fpic), then the variables defined in the compilation unit are
 * to be given preference over definitions of the same variables in shared
 * libraries. Hence when compiled using -fPIE/-fpie, local globals
 * (type 2 above) are also guaranteed to be generated using RIP-relative
 * addressing just like static globals.
 *
 *****************************************************************************
 * Calculating the enclave base address securely
 *
 * The enclave can be loaded at any address in memory. Only the host knows
 * the address where the enclave is loaded. So how can an enclave know its
 * base address?
 *
 * Strategy 1:
 *    Let the host set a variable oe_enclave_base within the enclave after
 *    loading. This approach is not safe since the host is untrusted and could
 *    set an arbitrary value and trick the enclave to writing secrets to host
 *    memory.
 *
 * Strategy 2:
 *    Define a variable called _enclave_rva (relative virtual address).
 *    The _enclave_rva is supposed to be set to the offset of that variable
 *    within the enclave image (i.e. as if the enclave was loaded to memory
 *    address 0). This offset value is a constant and therefore the enclave
 *    is signed after setting _enclave_rva to this value.
 *
 *    Actual runtime address of _enclave_rva minus the predetermined offset
 *    of _enclave_rva gives the runtime base address of the enclave:
 *       enclave-base-address = &_enclave_rva - _enclave_rva;
 *
 *    If the host sets _enclave_rva to an arbitrary value, then the loading
 *    the enclave will fail since the signature (generated with incorrect
 *    _enclave_rva value) will not match the signature embedded by the
 *    oesign tool (using the correct _enclave_rva value).
 *
  *****************************************************************************
 * Applying relocations
 *
 * Relocations are done within the enclave and relocation entries are measured
 * as part of enclave signing. This makes relocations secure.
 * Performing relocations involves adding the enclave base address to
 * each relocation entry (see reloc.c in linux/windows).
 * The Global Offset Table (GOT) is updated via performing the relocations.
 * This means that the _enclave_rva variable and other variables used for
 * relocations must not themselves be placed in the GOT. The simplest
 * (though not the only) way to enforce RIP-relative addressing is to
 * put all the relocation related variables into static global struct.
 *
 * Since the relocation values are supposed to be set by the loader,
 * unbeknownst to the compiler, they must be volatile qualified to prevent
 * compiler optimizations.
 *
 **/

static volatile uint64_t _enclave_rva;
static volatile uint64_t _reloc_rva;
static volatile uint64_t _reloc_size;

#endif

/*
**==============================================================================
**
** Enclave boundaries:
**
**==============================================================================
*/

const void* __oe_get_enclave_base()
{
#if defined(__linux__)
    return (uint8_t*)&_enclave_rva - _enclave_rva;
#else
    /*
     * Note: In windows, the reference to &oe_image_info will be compiled
     * IP-relative by the C-compiler on x86_64, and hence does not have a
     * relocation entry. Thus it works both pre- and post-relocation.
     */
    return (uint8_t*)&oe_enclave_properties_sgx -
           oe_enclave_properties_sgx.image_info.oeinfo_rva;
#endif
}

size_t __oe_get_enclave_size()
{
    return oe_enclave_properties_sgx.image_info.enclave_size;
}

/*
**==============================================================================
**
** Reloc boundaries:
**
**==============================================================================
*/

const void* __oe_get_reloc_base()
{
    const unsigned char* base = __oe_get_enclave_base();

#if defined(__linux__)
    return base + _reloc_rva;
#else
    return base + oe_enclave_properties_sgx.IMAGE_INFO.reloc_rva;
#endif
}

const void* __oe_get_reloc_end()
{
    return (const uint8_t*)__oe_get_reloc_base() + __oe_get_reloc_size();
}

size_t __oe_get_reloc_size()
{
#if defined(__linux__)
    return _reloc_size;
#else
    return oe_enclave_properties_sgx.image_info.reloc_size;
#endif
}

/*
**==============================================================================
**
** Heap boundaries:
**
**==============================================================================
*/

const void* __oe_get_heap_base()
{
    const unsigned char* base = __oe_get_enclave_base();

    return base + oe_enclave_properties_sgx.image_info.heap_rva;
}

size_t __oe_get_heap_size()
{
    return oe_enclave_properties_sgx.header.size_settings.num_heap_pages *
           OE_PAGE_SIZE;
}

const void* __oe_get_heap_end()
{
    return (const uint8_t*)__oe_get_heap_base() + __oe_get_heap_size();
}

/*
**==============================================================================
**
** oe_enclave:
**
**     The enclave handle obtained with oe_create_enclave() and passed
**     to the enclave during initialization (via OE_ECALL_INIT_ENCLAVE).
**
**==============================================================================
*/

oe_enclave_t* oe_enclave;

oe_enclave_t* oe_get_enclave(void)
{
    return oe_enclave;
}

/*
**==============================================================================
**
** oe_pid, oe_ppid, oe_uid, oe_euid
**
**     The process and user information with oe_create_enclave() and passed
**     to the enclave during initialization (via OE_ECALL_INIT_ENCLAVE).
**
**==============================================================================
*/

pid_t oe_pid;
pid_t oe_ppid; // Parent PID
pid_t oe_pgrp; // Process Group ID
uid_t oe_uid;  // user id
uid_t oe_euid; // effective user id

uint32_t oe_num_groups;

gid_t oe_groups[OE_NGROUP_MAX];

pid_t oe_getpid(void)
{
    return oe_pid;
}

pid_t oe_getppid(void)
{
    return oe_ppid;
}

pid_t oe_getpgrp(void)
{
    return oe_pgrp;
}

uid_t oe_getuid(void)
{
    return oe_uid;
}

uid_t oe_geteuid(void)
{
    return oe_euid;
}

int32_t oe_getgroups(uint32_t num_groups, gid_t* pgroups)
{
    int32_t retval = -1;

    if (num_groups)
    {
        if (!pgroups)
        {
            oe_errno = EFAULT;
            retval = -1;
            goto done;
        }
        if (num_groups > OE_NGROUP_MAX)
        {
            oe_errno = EINVAL;
            retval = -1;
            goto done;
        }

        memcpy(pgroups, oe_groups, oe_num_groups * sizeof(gid_t));
    }
    else
    {
        retval = (int32_t)oe_num_groups;
    }
done:
    return retval;
}

/*
**==============================================================================
**
** Page-oriented convenience functions.
**
**==============================================================================
*/

uint64_t oe_get_base_heap_page(void)
{
    const uint64_t heap_base = (uint64_t)__oe_get_heap_base();
    const uint64_t enclave_base = (uint64_t)__oe_get_enclave_base();
    return (heap_base - enclave_base) / OE_PAGE_SIZE;
}

uint64_t oe_get_num_heap_pages(void)
{
    return __oe_get_heap_size() / OE_PAGE_SIZE;
}

uint64_t oe_get_num_pages(void)
{
    return __oe_get_enclave_size() / OE_PAGE_SIZE;
}
