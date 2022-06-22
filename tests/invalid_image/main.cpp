// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/load.h>
#include <openenclave/internal/tests.h>

int main(int, char* argv[])
{
    oe_enclave_image_t image{};
    // expect failure
    // Linux  : ELF type is EXEC and not DYN
    // Windows: image is not ELF
    OE_TEST(oe_load_elf_enclave_image(argv[0], &image) == OE_INVALID_IMAGE);
}
