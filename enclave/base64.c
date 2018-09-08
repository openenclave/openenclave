#include <mbedtls/base64.h>
#include <openenclave/host.h>
#include <openenclave/internal/base64.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

/* The standard line width for base-64 encoding is 64 bytes */
static const size_t LINE_WIDTH = 64;

/* Adjust the required size to include add_line_breaks if requested */
static size_t _adjust_required_size(size_t size, bool add_line_breaks)
{
    if (add_line_breaks)
        return size + (size + LINE_WIDTH - 1) / LINE_WIDTH;
    else
        return size;
}

oe_result_t oe_base64_encode(
    const uint8_t* raw_data,
    size_t raw_size,
    bool add_line_breaks,
    uint8_t* base64_data,
    size_t* base64_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t required_size = 0;
    size_t size = 0;

    if (!raw_data || !base64_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!base64_data && *base64_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Determine the required size of the buffer. This might be a slight
    // overestimate.
    {
        int rc = mbedtls_base64_encode(NULL, 0, &size, raw_data, raw_size);

        if (rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
            OE_RAISE(OE_FAILURE);
    }

    /* Adjust the required size to include add_line_breaks */
    required_size = _adjust_required_size(size, add_line_breaks);

    /* If caller's buffer is too small, raise an error. */
    if (*base64_size < required_size)
    {
        *base64_size = required_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Perform base-64 encoding */
    {
        uint8_t buffer[size];

        if (mbedtls_base64_encode(buffer, size, &size, raw_data, raw_size) != 0)
            OE_RAISE(OE_FAILURE);

        /* Adjust the required size for any overestimate */
        required_size = _adjust_required_size(size, add_line_breaks);

        /* Copy base-64 encoded data to the caller's buffer */
        for (size_t i = 0, offset = 0; i < size; i++)
        {
            base64_data[offset++] = buffer[i];

            if (add_line_breaks)
            {
                if ((((i + 1) % LINE_WIDTH) == 0) || (i + 1 == size))
                    base64_data[offset++] = '\n';
            }
        }

        *base64_size = required_size;
    }

    result = OE_OK;

done:

    return result;
}
