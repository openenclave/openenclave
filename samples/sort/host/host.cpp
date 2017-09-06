#include <openenclave/host.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "../args.h"

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    printf("==== %s\n", argv[0]);

    /* Check argument count */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    /* Create an enclave from the file given by argv[1] */
    {
        const uint64_t flags = OE_FLAG_DEBUG | OE_FLAG_SIMULATE;

        if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
            OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    /* Call into Hello() function in the enclave */
    {
        Args args;

        size_t data[] = { 2, 1, 4, 5, 3, 10, 6, 7, 8, 9 };
        size_t size = OE_COUNTOF(data);

        args.data = data;
        args.size = size;

        if ((result = OE_CallEnclave(enclave, "Sort", &args)) != OE_OK)
            OE_PutErr("OE_CallEnclave() failed: result=%u", result);

        for (size_t i = 0; i < size; i++)
        {
            printf("%zu ", data[i]);
        }

        printf("\n\n");
    }

    /* Terminate the enclave */
    OE_TerminateEnclave(enclave);

    return 0;
}
