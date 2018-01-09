#define OE_TRACE_LEVEL 1
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openenclave/host.h>
#include <openenclave/bits/mem.h>
#include <openenclave/bits/elf.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/str.h>
#include <openenclave/bits/error.h>
#include "../host/enclave.h"

static const char* arg0;

void _MemReverse(void* dest_, const void* src_, size_t n)
{
    unsigned char* dest = (unsigned char*)dest_;
    const unsigned char* src = (const unsigned char*)src_;
    const unsigned char* end = src + n;

    while (n--)
        *dest++ = *--end;
}

void DumpHex(
    const unsigned char* data,
    size_t size)
{
    size_t i;

    for (i = 0; i < size; i++)
        printf("%02x", data[i]);

    printf("\n");
}

void DumpSigstruct(const SGX_SigStruct* p)
{
    printf("=== Sigstruct\n");
    printf("header="); DumpHex(p->header, sizeof(p->header));
    printf("type=%08x\n", p->type);
    printf("vendor=%08x\n", p->vendor);
    printf("date=%08x\n", p->date);
    printf("header2="); DumpHex(p->header2, sizeof(p->header2));
    printf("swdefined=%08x\n", p->swdefined);
    printf("modulus="); DumpHex(p->modulus, sizeof(p->modulus));
    printf("exponent="); DumpHex(p->exponent, sizeof(p->exponent));
    printf("signature="); DumpHex(p->signature, sizeof(p->signature));
    printf("miscselect=%08x\n", p->miscselect);
    printf("miscmask=%08x\n", p->miscmask);
    printf("attributes.flags=%016lx\n", p->attributes.flags);
    printf("attributes.xfrm=%016lx\n", p->attributes.xfrm);
    printf("attributemask.flags=%016lx\n", p->attributemask.flags);
    printf("attributemask.xfrm=%016lx\n", p->attributemask.xfrm);
    printf("enclavehash="); DumpHex(p->enclavehash, sizeof(p->enclavehash));
    printf("isvprodid=%04x\n", p->isvprodid);
    printf("isvsvn=%04x\n", p->isvsvn);
    printf("q1="); DumpHex(p->q1, sizeof(p->q1));
    printf("q2="); DumpHex(p->q2, sizeof(p->q2));
}

static OE_Result _GetDate(unsigned int* date)
{
    OE_Result result = OE_UNEXPECTED;
    time_t t;
    struct tm tm;
    size_t i;

    if (!date)
        OE_THROW(OE_INVALID_PARAMETER);

    t = time(NULL);

    if (localtime_r(&t, &tm) == NULL)
        OE_THROW(OE_FAILURE);

    {
        char s[9];
        unsigned char b[8];

        snprintf(s, sizeof(s), "%04u%02u%02u",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);

        for (i = 0; i < sizeof(b); i++)
            b[i] = s[i] - '0';

        *date = (b[0] << 28) | (b[1] << 24) | (b[2] << 20) | (b[3] << 16) |
            (b[4] << 12) | (b[5] << 8) | (b[6] << 4) | b[7];

#if 0
        *date = 0x20170705;
#endif
    }

    result = OE_OK;

catch:
    return result;
}

static OE_Result _GetModulus(
    RSA* rsa,
    uint8_t modulus[OE_KEY_SIZE])
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buf[OE_KEY_SIZE];

    if (!rsa || !modulus)
        OE_THROW(OE_INVALID_PARAMETER);

#if 0
    fprintf(stderr, "modulus.bytes=%u\n", BN_num_bytes(rsa->n));
#endif

    if (!BN_bn2bin(rsa->n, buf))
        OE_THROW(OE_FAILURE);

    _MemReverse(modulus, buf, OE_KEY_SIZE);

    result = OE_OK;

catch:
    return result;
}

static OE_Result _GetExponent(
    RSA* rsa,
    uint8_t exponent[OE_EXPONENT_SIZE])
{
    OE_Result result = OE_UNEXPECTED;
    //uint8_t buf[OE_EXPONENT_SIZE];

    if (!rsa || !exponent)
        OE_THROW(OE_INVALID_PARAMETER);

    if (rsa->e->top != 1)
        OE_THROW(OE_FAILURE);

    {
        unsigned long long x = rsa->e->d[0];
        exponent[0] = (x & 0x00000000000000FF) >> 0;
        exponent[1] = (x & 0x000000000000FF00) >> 8;
        exponent[2] = (x & 0x0000000000FF0000) >> 16;
        exponent[3] = (x & 0x00000000FF000000) >> 24;
    }

#if 0
    if (!BN_bn2bin(rsa->e, buf))
        OE_THROW(OE_FAILURE);

    printf("d=%lx\n", rsa->e->d[0]);

    DumpHex(buf, sizeof(buf));

    _MemReverse(exponent, buf, OE_EXPONENT_SIZE);

    DumpHex(exponent, OE_EXPONENT_SIZE);

    exit(0);
#endif

    result = OE_OK;

catch:
    return result;
}

OE_Result _GetQ1AndQ2(
    const void* signature,
    size_t signatureSize,
    const void* modulus,
    size_t modulusSize,
    void* q1Out,
    size_t q1OutSize,
    void* q2Out,
    size_t q2OutSize)
{
    OE_Result result = OE_UNEXPECTED;
    BIGNUM* s = NULL;
    BIGNUM* m = NULL;
    BIGNUM* q1 = NULL;
    BIGNUM* q2 = NULL;
    BIGNUM* t1 = NULL;
    BIGNUM* t2 = NULL;
    BN_CTX* ctx = NULL;
    unsigned char q1buf[q1OutSize + 8];
    unsigned char q2buf[q2OutSize + 8];
    unsigned char sbuf[signatureSize];
    unsigned char mbuf[modulusSize];

    if (!signature || !signatureSize || !modulus || !modulusSize ||
        !q1Out || !q1OutSize || !q2Out || !q2OutSize)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    memset(sbuf, 0, sizeof(sbuf));
    memset(mbuf, 0, sizeof(mbuf));

    _MemReverse(sbuf, signature, sizeof(sbuf));
    _MemReverse(mbuf, modulus, sizeof(mbuf));

    /* Create new objects */
    {
        if (!(s = BN_bin2bn(sbuf, sizeof(sbuf), NULL)))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(m = BN_bin2bn(mbuf, sizeof(mbuf), NULL)))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(q1 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(q2 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(t1 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(t2 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(ctx = BN_CTX_new()))
            OE_THROW(OE_OUT_OF_MEMORY);
    }

    /* Perform arithmetic */
    {
        if (!BN_mul(t1, s, s, ctx))
            OE_THROW(OE_FAILURE);

        if (!BN_div(q1, t2, t1, m, ctx))
            OE_THROW(OE_FAILURE);

        if (!BN_mul(t1, s, t2, ctx))
            OE_THROW(OE_FAILURE);

        if (!BN_div(q2, t2, t1, m, ctx))
            OE_THROW(OE_FAILURE);
    }

#if 0
    fprintf(stderr, "s.bytes=%d\n", BN_num_bytes(s));
    fprintf(stderr, "m.bytes=%d\n", BN_num_bytes(m));
    fprintf(stderr, "q1.bytes=%d\n", BN_num_bytes(q1));
    fprintf(stderr, "q2.bytes=%d\n", BN_num_bytes(q2));
#endif

    /* Copy Q1 to Q1OUT parameter */
    {
        size_t n = BN_num_bytes(q1);

        if (n > sizeof(q1buf))
            OE_THROW(OE_FAILURE);

        if (n > q1OutSize)
            n = q1OutSize;

        BN_bn2bin(q1, q1buf);
        _MemReverse(q1Out, q1buf, n);
    }

    /* Copy Q2 to Q2OUT parameter */
    {
        size_t n = BN_num_bytes(q2);

        if (n > sizeof(q2buf))
            OE_THROW(OE_FAILURE);

        if (n > q2OutSize)
            n = q2OutSize;

        BN_bn2bin(q2, q2buf);
        _MemReverse(q2Out, q2buf, n);
    }

    result = OE_OK;

catch:

    if (s)
        BN_free(s);
    if (m)
        BN_free(m);
    if (q1)
        BN_free(q1);
    if (q2)
        BN_free(q2);
    if (t1)
        BN_free(t1);
    if (t2)
        BN_free(t2);
    if (ctx)
        BN_CTX_free(ctx);

    return result;
}

OE_Result _InitSigstruct(
    SGX_SigStruct* sigstruct,
    const OE_SHA256* mrenclave,
    RSA* rsa)
{
    OE_Result result = OE_UNEXPECTED;

    if (!sigstruct)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Zero-fill the structure */
    memset(sigstruct, 0, sizeof(SGX_SigStruct));

    /* SGX_SigStruct.header */
    {
        const uint8_t bytes[] =
        {
            0x06,0x00,0x00,0x00,0xe1,0x00,
            0x00,0x00,0x00,0x00,0x01,0x00
        };

        memcpy(sigstruct->header, bytes, sizeof(sigstruct->header));
    }

    /* SGX_SigStruct.type */
    sigstruct->type = 0;

    /* SGX_SigStruct.vendor */
    sigstruct->vendor = 0;

    /* SGX_SigStruct.date */
    OE_TRY(_GetDate(&sigstruct->date));

    /* SGX_SigStruct.header2 */
    {
        const uint8_t bytes[] =
        {
            0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
            0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        };

        memcpy(sigstruct->header2, bytes, sizeof(sigstruct->header2));
    }

    /* SGX_SigStruct.swdefined */
    sigstruct->swdefined = 0;

    /* SGX_SigStruct.date */
    OE_TRY(_GetModulus(rsa, sigstruct->modulus));

    /* SGX_SigStruct.date */
    OE_TRY(_GetExponent(rsa, sigstruct->exponent));

    /* SGX_SigStruct.signature: fill in after other fields */

    /* SGX_SigStruct.miscselect (ATTN: ?) */
    sigstruct->miscselect = 0x00000000;

    /* SGX_SigStruct.miscmask (ATTN: ?) */
    sigstruct->miscmask = 0xFFFFFFFF;

    /* SGX_SigStruct.attributes (ATTN: ?) */
    sigstruct->attributes.flags = 0x0000000000000004;
    sigstruct->attributes.xfrm = 0x0000000000000003;

    /* SGX_SigStruct.attributemask (ATTN: ?) */
    sigstruct->attributemask.flags = 0xFFFFFFFFFFFFFFFd;
    sigstruct->attributemask.xfrm = 0xFFFFFFFFFFFFFFFb;

    /* SGX_SigStruct.enclavehash */
    memcpy(sigstruct->enclavehash, mrenclave, sizeof(sigstruct->enclavehash));

    /* SGX_SigStruct.isvprodid (ATTN: ?) */
    sigstruct->isvprodid = 0;

    /* SGX_SigStruct.isvsvn (ATTN: ?) */
    sigstruct->isvsvn = 0;

    /* Sign header and body sections of SigStruct */
    {
        unsigned char buf[sizeof(SGX_SigStruct)];
        size_t n = 0;

        memcpy(buf, SGX_SigStructHeader(sigstruct), SGX_SigStructHeaderSize());
        n += SGX_SigStructHeaderSize();
        memcpy(&buf[n], SGX_SigStructBody(sigstruct), SGX_SigStructBodySize());
        n += SGX_SigStructBodySize();

        {
            OE_SHA256 sha256;
            OE_SHA256Context context;
            unsigned char signature[OE_KEY_SIZE];
            unsigned int signatureSize;

            OE_SHA256Init(&context);
            OE_SHA256Update(&context, buf, n);
            OE_SHA256Final(&context, &sha256);

            if (!RSA_sign(
                NID_sha256,
                sha256.buf,
                sizeof(sha256),
                signature,
                &signatureSize,
                rsa))
            {
                fprintf(stderr, "OOPS!\n");
                exit(1);
            }

            if (sizeof(sigstruct->signature) != signatureSize)
                OE_THROW(OE_FAILURE);

            /* The signature is backwards and needs to be reversed */
            _MemReverse(sigstruct->signature, signature, sizeof(signature));
        }

    }

#if 1
    OE_TRY(_GetQ1AndQ2(
        sigstruct->signature,
        sizeof(sigstruct->signature),
        sigstruct->modulus,
        sizeof(sigstruct->modulus),
        sigstruct->q1,
        sizeof(sigstruct->q1),
        sigstruct->q2,
        sizeof(sigstruct->q2)));
#endif

    result = OE_OK;

catch:
    return result;
}

//
// Replace .so-extension with .signed.so. If there is no .so extension,
// append .signed.so.
//
static char* _MakeSignedLibName(
    const char* path)
{
    const char* p;
    mem_t buf = MEM_DYNAMIC_INIT;

    if ((!(p = strrchr(path, '.'))) || (strcmp(p, ".so") != 0))
        p = path + strlen(path);

    mem_append(&buf, path, p - path);
    mem_append(&buf, ".signed.so", 11);

    return mem_steal(&buf);
}

static int _SignAndWriteSharedLib(
    const char* path,
    size_t numHeapPages,
    size_t numStackPages,
    size_t numTCS,
    const OE_EnclaveSettings* settings,
    const SGX_SigStruct* sigstruct)
{
    int rc = -1;
    Elf64 elf;
    const char secname[] = ".oesig";
    FILE* os = NULL;

    /* Open ELF file */
    if (Elf64_Load(path, &elf) != 0)
    {
        fprintf(stderr, "%s: cannot load ELF file: %s\n", arg0, path);
        goto done;
    }

    /* Fail if the section already exists */
    {
        const void* data;
        size_t size;

        if (Elf64_FindSection(&elf, secname, &data, &size) == 0)
        {
            fprintf(stderr, "%s: file already signed: %s\n", arg0, path);
            goto done;
        }
    }

    /* Verify that this enclave contains required symbols */
    {
        Elf64_Sym sym;

        if (Elf64_FindSymbolByName(&elf, "OE_Main", &sym) != 0)
        {
            fprintf(stderr, "%s: OE_Main() undefined\n", arg0);
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_numPages", &sym) != 0)
        {
            fprintf(stderr, "%s: __oe_numPages undefined\n", arg0);
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_baseHeapPage", &sym) != 0)
        {
            fprintf(stderr, "%s: __oe_baseHeapPage undefined\n", arg0);
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_numHeapPages", &sym) != 0)
        {
            fprintf(stderr, "%s: __oe_numHeapPages undefined\n", arg0);
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_virtualBaseAddr", &sym) != 0)
        {
            fprintf(stderr, "%s: __oe_virtualBaseAddr undefined\n", arg0);
            goto done;
        }
    }

    /* Add the new section */
    {
        OE_SignatureSection sec;
        sec.magic = OE_META_MAGIC;
        sec.settings = *settings;
        sec.sigstruct = *sigstruct;

        if (Elf64_AddSection(
            &elf,
            secname,
            SHT_PROGBITS,
            &sec,
            sizeof(sec)) != 0)
        {
            fprintf(stderr, "%s: failed to add section\n", arg0);
            goto done;
        }
    }

    /* Write new shared shared library */
    {
        char* p = _MakeSignedLibName(path);

        if (!p)
        {
            fprintf(stderr, "%s: bad shared library name: %s\n", arg0, path);
            goto done;
        }

        if (!(os = fopen(p, "wb")))
        {
            fprintf(stderr, "%s: failed to open: %s\n", arg0, p);
            goto done;
        }

        if (fwrite(elf.data, 1, elf.size, os) != elf.size)
        {
            fprintf(stderr, "%s: failed to write: %s\n", arg0, p);
            goto done;
        }

        fclose(os);
        os = NULL;

        printf("Created %s\n", p);

        free(p);
    }

    rc = 0;

done:

    if (os)
        fclose(os);

    Elf64_Unload(&elf);

    return rc;
}

int LoadConfigFile(
    const char* path,
    OE_EnclaveSettings* settings)
{
    int rc = -1;
    FILE* is = NULL;
    int r;
    str_t str = STR_NULL_INIT;
    str_t lhs = STR_NULL_INIT;
    str_t rhs = STR_NULL_INIT;
    size_t line = 1;

    memset(settings, 0, sizeof(OE_EnclaveSettings));

    if (!(is = fopen(path, "rb")))
        goto done;

    if (str_dynamic(&str, NULL, 0) != 0)
        goto done;

    if (str_dynamic(&lhs, NULL, 0) != 0)
        goto done;

    if (str_dynamic(&rhs, NULL, 0) != 0)
        goto done;

    for (; (r = str_fgets(&str, is)) == 0; line++)
    {
        /* Remove leading and trailing whitespace */
        str_ltrim(&str, " \t");
        str_rtrim(&str, " \t\n");

        /* Skip comments and empty lines */
        if (str_ptr(&str)[0] == '#' || str_len(&str) == 0)
            continue;

        /* Split string about '=' character */
        if (str_split(&str, " \t=", &lhs, &rhs) != 0 ||
            str_len(&lhs) == 0 || str_len(&rhs) == 0)
        {
            fprintf(stderr, "%s: %s(%zu): syntax error\n", arg0, path, line);
            goto done;
        }

        /* Handle each setting */
        if (strcmp(str_ptr(&lhs), "Debug") == 0)
        {
            if (str_u64(&rhs, &settings->debug) != 0)
            {
                fprintf(stderr, "%s: %s(%zu): bad value for 'Debug'\n",
                    arg0, path, line);
                goto done;
            }
        }
        else if (strcmp(str_ptr(&lhs), "NumHeapPages") == 0)
        {
            if (str_u64(&rhs, &settings->numHeapPages) != 0)
            {
                fprintf(stderr, "%s: %s(%zu): bad value for 'NumHeapPages'\n",
                    arg0, path, line);
                goto done;
            }
        }
        else if (strcmp(str_ptr(&lhs), "NumStackPages") == 0)
        {
            if (str_u64(&rhs, &settings->numStackPages) != 0)
            {
                fprintf(stderr, "%s: %s(%zu): bad value for 'NumStackPages'\n",
                    arg0, path, line);
                goto done;
            }
        }
        else if (strcmp(str_ptr(&lhs), "NumTCS") == 0)
        {
            if (str_u64(&rhs, &settings->numTCS) != 0)
            {
                fprintf(stderr, "%s: %s(%zu): bad value for 'NumTCS'\n",
                    arg0, path, line);
                goto done;
            }
        }
        else
        {
            fprintf(stderr, "%s: %s(%zu): unknown setting: '%s'\n",
                arg0, path, line, str_ptr(&rhs));
            goto done;
        }

#if 0
        printf("{%s}={%s}\n", str_ptr(&lhs), str_ptr(&rhs));
#endif
    }

    rc = 0;

done:

    str_free(&str);
    str_free(&lhs);
    str_free(&rhs);

    if (is)
        fclose(is);

    return rc;
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    int ret = 1;
    OE_Result result;
    OE_SGXDevice* dev = NULL;
    size_t numHeapPages = 2;
    size_t numStackPages = 1;
    size_t numTCS = 2;
    OE_SHA256 mrenclave = OE_SHA256_INIT;
    OE_EnclaveSettings settings;
    SGX_SigStruct sigstruct;
    FILE* is = NULL;
    RSA* rsa = NULL;
    const char* enclave;
    const char* conffile;
    const char* keyfile;
    OE_Enclave enc;

    /* Check arguments */
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s ENCLAVE CONFFILE KEYFILE\n", arg0);
        exit(1);
    }

    /* Collect arguments */
    enclave = argv[1];
    conffile = argv[2];
    keyfile = argv[3];

    /* Load the configuration file */
    if (LoadConfigFile(conffile, &settings) != 0)
        OE_PutErr("failed to load configuration file: %s\n", conffile);

    /* Open the MEASURER to compute MRENCLAVE */
    if (!(dev = __OE_OpenSGXMeasurer()))
        OE_PutErr("__OE_OpenSGXDriver() failed");

    /* Build an enclave to obtain the MRENCLAVE measurement */
    if ((result = __OE_BuildEnclave(dev, enclave, &settings,
        false, false, &enc)) != OE_OK)
    {
        OE_PutErr("__OE_BuildEnclave(): result=%u", result);
    }

    /* Open the key file */
    if (!(is = fopen(keyfile, "rb")))
    {
        OE_PutErr("failed to load keyfile: %s\n", keyfile);
        goto done;
    }

    /* Open the certificate file */
    if (!(rsa = PEM_read_RSAPrivateKey(is, &rsa, NULL, NULL)))
    {
        fprintf(stderr, "%s: failed to create certificate\n", arg0);
        goto done;
    }

    /* Get the MRENCLAVE value */
    if ((result = dev->gethash(dev, &mrenclave)) != OE_OK)
        OE_PutErr("Failed to get hash: result=%u", result);

    /* Initialize the SigStruct object */
    if ((result = _InitSigstruct(&sigstruct, &mrenclave, rsa) != 0))
        OE_PutErr("_InitSigstruct() failed: result=%u", result);

    /* Create signature section and write out new file */
    if ((result = _SignAndWriteSharedLib(
        enclave,
        numHeapPages,
        numStackPages,
        numTCS,
        &settings,
        &sigstruct)) != OE_OK)
    {
        OE_PutErr("_SignAndWriteSharedLib(): result=%u", result);
    }

#if 0
    printf("MRENCLAVE=%s\n", OE_SHA256StrOf(&mrenclave).buf);
    DumpSigstruct(&sigstruct);
#endif

    ret = 0;

done:

    if (is)
        fclose(is);

    if (dev)
        dev->close(dev);

    if (rsa)
        RSA_free(rsa);

    return ret;
}
