// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <enc/defs.h>
#include <enc/sha.h>
#include <enc/types.h>
#include <enc/utils.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define PAGE_SIZE 4096

using namespace std;

struct Entry
{
    unsigned long long vaddr;
    unsigned long long flags;
    unsigned int attr;
};

struct Page
{
    unsigned char buf[PAGE_SIZE];
};

int LoadFile(const char* path, size_t extraBytes, void** data, size_t* size)
{
    int rc = -1;
    FILE* is = NULL;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!path || !data || !size)
        goto done;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        *size = st.st_size;
    }

    /* Allocate memory */
    if (!(*data = malloc(*size + extraBytes)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(*data, 1, *size, is) != *size)
        goto done;

    /* Zero-fill any extra bytes */
    if (extraBytes)
        memset((unsigned char*)*data + *size, 0, extraBytes);

    rc = 0;

done:

    if (rc != 0)
    {
        if (data && *data)
        {
            free(*data);
            *data = NULL;
        }

        if (size)
            *size = 0;
    }

    if (is)
        fclose(is);

    return rc;
}

int LoadPages(const char* path, std::vector<Page>& v)
{
    void* data = NULL;
    size_t size;
    size_t npages;

    if (LoadFile(path, 0, &data, &size) != 0)
        return -1;

    if (size % PAGE_SIZE)
    {
        free(data);
        return -1;
    }

    npages = size / PAGE_SIZE;

    const Page* pages = (Page*)data;

    for (size_t i = 0; i < npages; i++)
        v.push_back(pages[i]);

    if (data)
        free(data);

    return 0;
}

static int ReadLog(const char* path, vector<Entry>& log)
{
    FILE* is;
    int n;

    if (!(is = fopen(path, "r")))
        return -1;

    do
    {
        Entry ent;
        n = fscanf(
            is,
            "EADD: flags=%llx vaddr=%llx sum=%*x content=%*x attr=%u\n",
            &ent.flags,
            &ent.vaddr,
            &ent.attr);

        if (n != 3)
            break;

        log.push_back(ent);
    } while (1);

    fclose(is);
    return 0;
}

void DumpCtx(OE_SHA256Context context)
{
    OE_SHA256 hash;
    OE_SHA256Final(&context, &hash);
    printf("%s\n", OE_SHA256StrOf(&hash).buf);
}

int MeasureECreate(OE_SHA256Context* context)
{
    struct ECreateMeasurement
    {
        char name[8];
        unsigned int ssa_frame_size;
        unsigned long long size;
        unsigned char reserved[44];
    } OE_PACKED;
    OE_CHECK_SIZE(sizeof(ECreateMeasurement), 64);
    struct ECreateMeasurement m;

    memset(&m, 0, sizeof(m));
    memcpy(m.name, "ECREATE", 8);
    m.ssa_frame_size = 1;
    m.size = 4194304;

    // 6942a219b9a4d745a4d90b9933ad98656456ab0cd96c6a9995a75880a1f9a5a3

    OE_SHA256Update(context, &m, sizeof(m));

    return 0;
}

int MeasureEExtend(
    OE_SHA256Context* context,
    unsigned long long vaddr,
    unsigned long long flags,
    const void* page)
{
    struct EEXtendMeasurement
    {
        char name[8];
        unsigned long long offset;
        unsigned char reserved[48];
    } OE_PACKED;
    OE_CHECK_SIZE(sizeof(EEXtendMeasurement), 64);
    struct EEXtendMeasurement m;
    unsigned long long offset = 0;

    printf("=== EEXTEND: vaddr=%016llx\n", vaddr);

    /* Write this page (256 bytes at a time) */
    while (offset < PAGE_SIZE)
    {
        size_t i;

        /* Write "EEXTEND" measurement */
        memset(&m, 0, sizeof(m));
        memcpy(m.name, "EEXTEND", 8);
        m.offset = vaddr + offset;

        OE_SHA256Update(context, &m, sizeof(m));

        /* Measure 64 bytes, 4 times */
        for (i = 0; i < 4; i++)
        {
            OE_SHA256Update(context, (unsigned char*)page + offset, 64);
            offset += 64;
            printf("OFFSET=%llu\n", offset);
        }

        DumpCtx(*context);
    }

    return 0;
}

int MeasureEAdd(
    OE_SHA256Context* context,
    unsigned long long vaddr,
    unsigned long long flags,
    unsigned long long attr,
    const void* page)
{
    struct EAddMeasurement
    {
        char name[8];
        unsigned long long offset;
        unsigned long long secinfo_flags;
        unsigned long long secinfo_reserved[5];
    } OE_PACKED;
    OE_CHECK_SIZE(sizeof(EAddMeasurement), 64);
    struct EAddMeasurement m;

    printf("=== EADD : flags=%llx vaddr=%016llx\n", flags, vaddr);
    printf("CHECKSUM=%u\n", OE_Checksum(page, PAGE_SIZE));

    memset(&m, 0, sizeof(m));
    memcpy(m.name, "EADD\0\0\0", 8);
    m.offset = vaddr;
    m.secinfo_flags = flags;
    OE_SHA256Update(context, &m, sizeof(m));

    DumpCtx(*context);

    if (attr & 2)
    {
        if (MeasureEExtend(context, vaddr, flags, page) != 0)
            return -1;
    }

    return 0;
}

int main(int argc, const char* argv[])
{
    vector<Entry> log;
    vector<Page> pages;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s log.txt. log.bin\n", argv[0]);
        exit(1);
    }

    if (ReadLog(argv[1], log) != 0)
    {
        fprintf(stderr, "%s: failed to read %s\n", argv[0], argv[1]);
        exit(1);
    }

#if 0
    for (size_t i = 0; i < log.size(); i++)
    {
        const Entry& ent = log[i];
        printf("vaddr=%016llx attr=%x\n", ent.vaddr, ent.attr);
    }
#endif

    if (LoadPages(argv[2], pages) != 0)
    {
        fprintf(stderr, "%s: failed to read %s\n", argv[0], argv[2]);
        exit(1);
    }

    if (pages.size() != log.size())
    {
        fprintf(stderr, "%s: page count confliect\n", argv[0]);
        exit(1);
    }

    OE_SHA256Context context;
    OE_SHA256Init(&context);

    OE_TEST(MeasureECreate(&context) == 0);

    for (size_t i = 0; i < log.size(); i++)
    {
        const Entry& ent = log[i];
        MeasureEAdd(&context, ent.vaddr, ent.flags, ent.attr, &pages[i]);
    }

    return 0;
}
