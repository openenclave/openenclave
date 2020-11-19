// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <openenclave/internal/bits/fcntl.h>
#include <openenclave/internal/dynlink.h>
#include <openenclave/internal/raise.h>
#include <stddef.h> //offsetof
#include <string.h>
#include <unistd.h> // for close()

#include <sys/stat.h>
#include "../memalign.h"

#include <openenclave/internal/hexdump.h>

/* TODO: Not Windows compatible, need to fix:
 * - path handling using strrchr
 * - use of pread, open, close
 * - use of linux specific protection flags (e.g. PROT_READ etc.)
 */
#if defined(_MSC_VER)
#include <Windows.h>
struct __stat64 statbuf;
#define _fstat64 fstat
#define _read read
#define S_ISREG(ST_MODE) (ST_MODE & _S_IFREG)
#else
#include <sys/mman.h>
#include <unistd.h>
struct stat statbuf;
#endif

#define MUSL_PATHNAME_MAX_LENGTH (2 * NAME_MAX + 2)

#define MAXP2(a, b) (-(-(a) & -(b)))

static oe_result_t _read_sections(int fd, dso_t* dso, elf64_ehdr_t* ehdr)
{
    oe_result_t result = OE_UNEXPECTED;
    bool has_build_id = false;
    elf64_shdr_t* shbuf = NULL;
    elf64_shdr_t* sh = NULL;
    elf64_xword_t shstrtab_size = 0;
    char* shstrtab = NULL;

    ssize_t l = 0;

    /* Read the sections table from file */
    size_t shsize = ehdr->e_shnum * ehdr->e_shentsize;
    if (!shsize)
        OE_RAISE_MSG(OE_INVALID_IMAGE, "Failed to read ELF sections", NULL);
    shbuf = (elf64_shdr_t*)malloc(shsize);
    if (!shbuf)
        OE_RAISE(OE_OUT_OF_MEMORY);
    l = pread(fd, shbuf, shsize, (off_t)ehdr->e_shoff);
    if (l < 0 || (size_t)l != shsize)
        OE_RAISE(OE_READ_FAILED);

    /* Read the section header string table from file */
    if (ehdr->e_shstrndx >= ehdr->e_shnum)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE,
            "ELF section header string table out of bounds",
            NULL);

    sh = &shbuf[ehdr->e_shstrndx];
    shstrtab_size = sh->sh_size;
    shstrtab = calloc(1, shstrtab_size);
    if (!shstrtab)
        OE_RAISE(OE_OUT_OF_MEMORY);
    l = pread(fd, shstrtab, shstrtab_size, (off_t)sh->sh_offset);
    if (l < 0 || (size_t)l != shstrtab_size)
        OE_RAISE(OE_READ_FAILED);

    /* The ELF spec requires the string table to have the first and last byte
     * equal to 0. Checking if the last byte is 0 also ensures that any pointer
     * within the table will be null terminated, because the table itself is
     * null terminated. */
    if (shstrtab_size < 2 || shstrtab[0] != '\0' ||
        shstrtab[shstrtab_size - 1] != '\0')
        OE_RAISE_MSG(
            OE_INVALID_IMAGE,
            "Failed to read ELF section header string table",
            NULL);

    /* Find sections for OE validation */
    for (size_t i = 0; i < ehdr->e_shnum; i++)
    {
        sh = &shbuf[i];
        if (sh->sh_type == SHT_NULL || sh->sh_type == SHT_NOBITS)
            continue;
        if (sh->sh_name)
        {
            if (sh->sh_name >= shstrtab_size)
                OE_RAISE_MSG(
                    OE_INVALID_IMAGE,
                    "Section name out of string table bounds",
                    NULL);
            const char* name = shstrtab + sh->sh_name;
            if (strcmp(name, ".oeinfo") == 0)
            {
                dso->oeinfo_rva = sh->sh_addr;
                dso->oeinfo_file_pos = sh->sh_offset;
                OE_TRACE_VERBOSE(
                    "Found properties block offset %lx size %lx",
                    sh->sh_offset,
                    sh->sh_size);
            }
            else if (strcmp(name, ".note.gnu.build-id") == 0)
            {
                has_build_id = true;
            }
        }
    }

    /* It is now the default for linux shared libraries and executables to
     * have the build-id note. GCC by default passes the --build-id option
     * to linker, whereas clang does not. Build-id is also used as a key by
     * debug symbol-servers. If no build-id is found emit a trace message.
     * */
    if (!has_build_id)
    {
        OE_TRACE_ERROR("Enclave image does not have build-id.");
    }
    result = OE_OK;

done:
    free(shbuf);
    shbuf = NULL;
    free(shstrtab);
    shstrtab = NULL;
    return result;
}

static void unmap_library(dso_t* dso)
{
    /* This has parity with _unload_elf_image in terms of
     * cleaning up the members of a dso_t. */
    if (dso)
    {
        oe_memalign_free(dso->map);
        free(dso->loadmap);
    }
}

/* This is the equivalent of the enclave _read_elf_header through
 * _stage_image_segments that caches the relevant ELF pointers on the DSO
 * object and loads the segments into memory */
static oe_result_t map_library(int fd, dso_t* dso)
{
    oe_result_t result = OE_OK;

    /* TODO: Determine why MUSL uses this buffer sizing with extra 896 bytes */
    elf64_ehdr_t buf[(896 + sizeof(elf64_ehdr_t)) / sizeof(elf64_ehdr_t)];
    void* allocated_buf = 0;
    size_t phsize;
    size_t addr_min = OE_SIZE_MAX, addr_max = 0;
    size_t map_len;
    size_t nsegs = 0;
    elf64_ehdr_t* eh;
    elf64_phdr_t *ph, *ph0;
    unsigned char* map = MAP_FAILED;
    unsigned char* base = NULL;
    size_t dyn = 0;
    size_t tls_image = 0;

    /* Read the ELF header, analogous to _read_elf_header */
    ssize_t l = read(fd, buf, sizeof(buf));
    eh = buf;

    if (l < 0)
        OE_RAISE(OE_READ_FAILED);
    if ((size_t)l < sizeof(*eh))
        OE_RAISE(OE_INVALID_IMAGE);

    /* Fail if not PIE or shared object. MUSL accepts ET_EXEC, but not OE */
    if (eh->e_type != ET_DYN)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not a PIE or shared object", NULL);

    /* OE specifically fails if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not Intel X86 64-bit", NULL);

    /* Scan ELF sections for .oeinfo and other OE required sections */
    OE_CHECK(_read_sections(fd, dso, eh));

    /* Read the program headers, analogous to _initialize_image_segments,
     * including the call to elf64_get_program_header */
    phsize = eh->e_phentsize * eh->e_phnum;
    if (phsize > sizeof buf - sizeof *eh)
    {
        allocated_buf = malloc(phsize);
        if (!allocated_buf)
            OE_RAISE(OE_OUT_OF_MEMORY);
        l = pread(fd, allocated_buf, phsize, (off_t)eh->e_phoff);
        if (l < 0 || (size_t)l != phsize)
            OE_RAISE(OE_READ_FAILED);
        ph = ph0 = allocated_buf;
    }
    else if (eh->e_phoff + phsize > (size_t)l)
    {
        l = pread(fd, buf + 1, phsize, (off_t)eh->e_phoff);
        if (l < 0 || (size_t)l != phsize)
            OE_RAISE(OE_READ_FAILED);
        ph = ph0 = (void*)(buf + 1);
    }
    else
    {
        ph = ph0 = (void*)((char*)buf + eh->e_phoff);
    }

    /* Read the program load segments */
    for (size_t i = eh->e_phnum; i;
         i--, ph = (void*)((char*)ph + eh->e_phentsize))
    {
        if (ph->p_type == PT_DYNAMIC)
        {
            dyn = ph->p_vaddr;
        }
        else if (ph->p_type == PT_TLS)
        {
            tls_image = ph->p_vaddr;
            dso->tls.align = ph->p_align;
            dso->tls.len = ph->p_filesz;
            dso->tls.size = ph->p_memsz;
        }
        if (ph->p_type != PT_LOAD)
            continue;
        nsegs++;
        if (ph->p_vaddr < addr_min)
        {
            addr_min = ph->p_vaddr;
        }
        if (ph->p_vaddr + ph->p_memsz > addr_max)
        {
            addr_max = ph->p_vaddr + ph->p_memsz;
        }
    }

    if (!dyn)
        OE_RAISE_MSG(OE_INVALID_IMAGE, "No PT_DYNAMIC segment found.", NULL);

    /* Note that this rounds down the minimum RVA as well, so may result in
     * an extra page of allocation compared to _initialize_image_segments
     * that may not allocate enough space to account for this */
    addr_max += PAGE_SIZE - 1;
    addr_max &= -PAGE_SIZE;
    addr_min &= -PAGE_SIZE;
    map_len = addr_max - addr_min;
    map = oe_memalign(OE_PAGE_SIZE, map_len);
    if (!map)
        OE_RAISE(OE_OUT_OF_MEMORY);
    memset(map, 0, map_len);

    /* Map the loadable program segments into memory so they are aligned and
     * can be loaded page-wise into the enclave, analogous to what
     * _stage_image_segments does */
    dso->loadmap =
        calloc(1, sizeof *dso->loadmap + nsegs * sizeof *dso->loadmap->segs);
    if (!dso->loadmap)
        OE_RAISE(OE_OUT_OF_MEMORY);
    dso->loadmap->nsegs = nsegs;

    ph = ph0;
    for (size_t i = 0; i < nsegs; ph = (void*)((char*)ph + eh->e_phentsize))
    {
        if (ph->p_type != PT_LOAD)
            continue;

        /* Each segment start must be a page aligned offset for the
         * add_segment_pages function later and we will use the addr to index
         * into the map for adding the segment pages */
        dso->loadmap->segs[i].addr = ((size_t)map + ph->p_vaddr);
        if (i > 0)
        {
            loadseg_t* prev_seg = &dso->loadmap->segs[i - 1];
            size_t prev_end = prev_seg->addr + prev_seg->p_memsz +
                              (prev_seg->p_vaddr % PAGE_SIZE);
            if (prev_end > dso->loadmap->segs[i].addr)
                OE_RAISE(
                    OE_UNEXPECTED,
                    "PT_LOAD segment start overlaps with previous segment",
                    dso->loadmap->segs[i].addr,
                    prev_end);
        }
        dso->loadmap->segs[i].p_vaddr = ph->p_vaddr;
        dso->loadmap->segs[i].p_memsz = ph->p_memsz;
        dso->loadmap->segs[i].p_flags = ph->p_flags;

        /* Note that if p_memsz > p_filesz, the rest of the memory is already
         * zeroed since loadmap is allocated with calloc */
        ssize_t read = pread(
            fd,
            (void*)dso->loadmap->segs[i].addr,
            ph->p_filesz,
            (off_t)ph->p_offset);
        if (read != (ssize_t)ph->p_filesz)
            OE_RAISE(OE_READ_FAILED);
        i++;
    }

    dso->map = map;
    dso->map_len = map_len;

    base = map - addr_min;
    dso->entry_rva = eh->e_entry; // For parity with _oe_enclave_elf_image
    dso->phdr = 0;
    dso->phnum = 0;
    ph = ph0;
    for (size_t i = eh->e_phnum; i;
         i--, ph = (void*)((char*)ph + eh->e_phentsize))
    {
        if (ph->p_type != PT_LOAD)
            continue;

        /* Check if the programs headers are in this load segment, and
         * if so, record the address for use by dl_iterate_phdr. */
        if (!dso->phdr && eh->e_phoff >= ph->p_offset &&
            eh->e_phoff + phsize <= ph->p_offset + ph->p_filesz)
        {
            dso->phdr =
                (void*)(base + ph->p_vaddr + (eh->e_phoff - ph->p_offset));
            dso->phnum = eh->e_phnum;
        }
    }

    dso->base = base;
    dso->dynv = laddr(dso, dyn);

    if (dso->tls.size)
        dso->tls.image = laddr(dso, tls_image);

    result = OE_OK;

done:
    if (result != OE_OK)
        unmap_library(dso);
    free(allocated_buf);
    allocated_buf = NULL;
    return result;
}

static inline int _set_dso_path_buffer(
    oe_dso_load_state_t* load_state,
    const char* shortname,
    char* path_buffer,
    size_t path_buffer_size)
{
    int required_path_length = 0;
    if (load_state->head)
    {
        /* Use the primary enclave DSO's root path if available */
        int root_path_length =
            (int)(strrchr(load_state->head->name, '/') - load_state->head->name);
        required_path_length = snprintf(
            path_buffer,
            path_buffer_size,
            "%.*s/%s",
            root_path_length,
            load_state->head->name,
            shortname);
    }
    else
    {
        /* Otherwise, all lookups must be relative to current directory */
        required_path_length =
            snprintf(path_buffer, path_buffer_size, "./%s", shortname);
    }
    return required_path_length;
}

/* OE version of load_library() from 3rdparty/musl/musl/ldso/dynlink.c */
oe_result_t oe_load_enclave_dso(
    const char* name,
    oe_dso_load_state_t* load_state,
    dso_t* needed_by,
    dso_t** dso)
{
    oe_result_t result = OE_UNEXPECTED;

    char pathname_buffer[MUSL_PATHNAME_MAX_LENGTH];
    char* pathname = NULL;
    int required_pathname_length = 0;
    const char* shortname = NULL;
    dso_t *p, temp_dso = {0};
    int fd = -1;
    size_t dso_alloc_size = 0;

    if (!name || !*name || !load_state)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check if the name provided is a pathed name, which is
     * usually provided for the primary dso */
    if (strchr(name, '/'))
    {
        /* Enforce OE max path length for _load_elf_image */
        if (strlen(name) > OE_INT32_MAX)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "Enclave path is not null-terminated or exceeds OE_INT32_MAX");

        pathname = (char*)name;
        shortname = strrchr(name, '/') + 1;
    }
    else
    {
        /* Limitation for consistency with MUSL libc loading */
        if (strlen(name) > NAME_MAX)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "Library name is not null-terminated or exceeds NAME_MAX");
        shortname = name;
    }

    /* Search for the name to see if it's already loaded */
    if (load_state->head)
    {
        for (p = load_state->head->next; p; p = p->next)
        {
            if (p->shortname && !strcmp(p->shortname, shortname))
            {
                if (dso)
                    *dso = p;
                result = OE_OK;
                goto done;
            }
        }
    }

    /* If name is not pathed, infer the path from the primary enclave DSO */
    if (!pathname)
    {
        required_pathname_length = _set_dso_path_buffer(
            load_state, shortname, pathname_buffer, sizeof(pathname_buffer));

        if (required_pathname_length <= 0)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (required_pathname_length < (int64_t)sizeof(pathname_buffer))
            pathname = pathname_buffer;
        else
        {
            size_t buffer_size = (size_t)required_pathname_length + 1;
            pathname = (char*)malloc(buffer_size);
            if (!pathname)
                OE_RAISE(OE_OUT_OF_MEMORY);

            required_pathname_length = _set_dso_path_buffer(
                load_state,
                shortname,
                pathname_buffer,
                sizeof(pathname_buffer));
        }
    }

    fd = open(pathname, O_RDONLY);
    if (fd < 0 || fstat(fd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode))
        OE_RAISE(OE_INVALID_PARAMETER);

    result = map_library(fd, &temp_dso);
    close(fd);
    OE_CHECK(result);

    decode_dyn(&temp_dso);

    /* TODO: Add additional check to block unsupported DT_TEXTREL for
     * parity with existing OE behavior */
    // {
    //     size_t dyn[DYN_CNT];
    //     decode_vec(p->dynv, dyn, DYN_CNT);
    //     if (search_vec(p->dynv, dyn, DT_TEXTREL))
    //         OE_RAISE(
    //             OE_UNSUPPORTED_ENCLAVE_IMAGE,
    //             "Enclave image contains unsupported DT_TEXTREL dynamic table
    //             " "entry.", NULL);
    // }

    /* Allocate storage for the new DSO. Note OE does not account for
     * dynamic loading scenarios where a reservation for all pre-existing
     * threads to obtain copies of the new TLS plus an extended DTV capable of
     * storing an additional slot for the newly-loaded DSO. */
    dso_alloc_size = sizeof *p + strlen(pathname) + 1;
    p = calloc(1, dso_alloc_size);
    if (!p)
    {
        unmap_library(&temp_dso);
        OE_RAISE(OE_OUT_OF_MEMORY);
    }
    memcpy(p, &temp_dso, sizeof temp_dso);
    p->needed_by = needed_by;
    p->name = p->buf;
    strcpy(p->name, pathname);
    p->shortname = strrchr(p->name, '/') + 1;

    if (p->tls.image)
    {
        p->tls_id = ++load_state->tls_cnt;
        load_state->tls_align = MAXP2(load_state->tls_align, p->tls.align);
        load_state->tls_offset += p->tls.size + p->tls.align - 1;
        load_state->tls_offset -=
            (load_state->tls_offset + (uintptr_t)p->tls.image) &
            (p->tls.align - 1);
        p->tls.offset = load_state->tls_offset;

        /* MUSL does additional work here to update the new_tls and new_dtv
         * needed for dynamic loading of modules with TLS that OE does not
         * support here. */
    }

    if (!load_state->head)
        load_state->head = load_state->tail = p;
    else
    {
        load_state->tail->next = p;
        p->prev = load_state->tail;
        load_state->tail = p;
    }

    if (dso)
        *dso = p;
    result = OE_OK;

done:
    if (required_pathname_length >= (int64_t)sizeof(pathname_buffer))
        free(pathname);

    return result;
}

oe_result_t oe_load_deps(oe_dso_load_state_t* load_state, dso_t* p)
{
    oe_result_t result = OE_UNEXPECTED;
    for (; p; p = p->next)
    {
        for (size_t i = 0; p->dynv[i]; i += 2)
        {
            if (p->dynv[i] != DT_NEEDED)
                continue;
            OE_CHECK(oe_load_enclave_dso(
                p->strings + p->dynv[i + 1], load_state, p, NULL));
        }
    }
    result = OE_OK;

done:
    return result;
}

void oe_unload_enclave_dso(oe_dso_load_state_t* load_state)
{
    if (load_state)
    {
        dso_t* next = NULL;
        for (dso_t* p = load_state->head; p; p = next)
        {
            next = p->next;
            unmap_library(p);
            free(p);
        }
    }
}

size_t oe_get_dso_size(dso_t* dso)
{
    size_t size = 0;
    if (dso)
    {
        size += sizeof(*dso);
        size += sizeof(void*) - 1;
        size &= -sizeof(void*);
    }
    return size;
}

size_t oe_get_dso_segments_size(dso_t* dso)
{
    size_t size = 0;
    if (dso)
        size += dso->map_len;
    return size;
}
