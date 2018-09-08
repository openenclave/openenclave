#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/base64.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>

oe_result_t oe_base64_encode(
    const uint8_t* raw_data,
    size_t raw_size,
    bool add_line_breaks,
    uint8_t* base64_data,
    size_t* base64_size)
{
    oe_result_t result = OE_UNEXPECTED;
    BIO *bio = NULL;
    BIO *b64 = NULL;

    if (!raw_data || !base64_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!base64_data && *base64_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(b64 = BIO_new(BIO_f_base64())))
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (!(bio = BIO_push(b64, bio)))
        OE_RAISE(OE_OUT_OF_MEMORY);
    b64 = NULL;

    if (!add_line_breaks)
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    if (BIO_write(bio, raw_data, raw_size) <= 0)
        OE_RAISE(OE_FAILURE);

    BIO_flush(bio);

    /* Copy the base-64 data to the caller's buffer */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_FAILURE);

        /* If buffer is too small */
        if (*base64_size < mem->length)
        {
            *base64_size = mem->length;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy result to output buffer */
        memcpy(base64_data, mem->data, mem->length);
        *base64_size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free_all(bio);

    if (b64)
        BIO_free(b64);

    return result;
}
