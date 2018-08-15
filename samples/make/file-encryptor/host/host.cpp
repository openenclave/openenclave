// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include "../args.h"



#include <iostream>
#include <map>
#include <string>
#include <iterator>

//#define DATA_BLOCK_SIZE (256*1024) // 256 KB buffer
#define DATA_BLOCK_SIZE 256

oe_enclave_t * enclave = NULL;

/*
#include <iostream>
#include <map>
#include <string>
#include <iterator>
std::map<oe_result_t, std::string> errorToStringMap;

void populate_error_code_map()
{
    OE_BAD_ALIGNMENT    i

    for (int i=(int)OE_OK; i<=(int)OE_BAD_ALIGMENT; i++)
    {
        errorToStringMap.insert(std::make_pair(oe_result_t, std::string(#ENUM)));
    }
}
*/

oe_result_t set_password(const char *password)
{
   oe_result_t result;

    result = oe_call_enclave(enclave, "set_password",  (void*)password);
    if (result != OE_OK)
    {
        fprintf(stderr, "oe_call_enclave(): %u\n", result);
   }
  return result;
}


oe_result_t initialize_encryptor(bool b_encrypt)
{
    EncryptArgs arg;
    oe_result_t result;
    arg.b_encrypt = true;

    result = oe_call_enclave(enclave, "initialize_encryptor",  (void*)&arg);
    if (result != OE_OK)
    {
        fprintf(stderr, "initialize_encryptor failed: %u\n", result);
    }
    return result;
}

oe_result_t crypt_block(unsigned char *inputbuffer, unsigned char *outputbuffer, size_t size)
{
    EncryptBlockArgs arg;
    oe_result_t result;
    arg.b_encrypt = true;
    arg.inputbuf = inputbuffer;
    arg.outputbuf = outputbuffer;
    arg.size = size;

    result = oe_call_enclave(enclave, "encryt_block",  (void*)&arg);
    if (result != OE_OK)
    {
        fprintf(stderr, "encryt_block failed: %u\n", result);
    }
    return result;
}

oe_result_t close_encryptor()
{
    EncryptArgs arg;
    oe_result_t result;
    arg.b_encrypt = true;

    result = oe_call_enclave(enclave, "close_encryption",  (void*)&arg);
    if (result != OE_OK)
    {
        fprintf(stderr, "initialize_encryption failed: %u\n", result);
    }
    return result;
}


int main(int argc, const char* argv[])
{
    oe_result_t result;
//    oe_enclave_t* enclave = NULL;
    int ret = 0;
    FILE* srcfile = NULL;
    FILE* destfile = NULL;
    unsigned char *rbuffer=NULL, *wbuffer=NULL;	
    size_t bread, bwritten;
    size_t blockcount = 0;
    char temp[DATA_BLOCK_SIZE+1];

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s source_file_name ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const char *psource_file = argv[1];
    printf("file to be process: (%s)\n", psource_file);
    const char *pdest_file= "./out.encrypted";
 

    printf("enclave image:(%s)\n", argv[2]);
    result = oe_create_enclave(
        argv[2],
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        fprintf(stderr, "oe_create_enclave() failed with %s %u\n", argv[0], result);
        ret = 1;
        goto cleanup;
    }

    // set password
    result = set_password("mybadpassword");
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: oe_create_enclave(): %u\n", argv[0], result);
        return 1;
    }

    //---------------------------
    // *** encryption
    //---------------------------

    // allocate buffers
    rbuffer = new unsigned char[DATA_BLOCK_SIZE]; // 256KB buffer size
    if (rbuffer == NULL) {
        printf("rbuffer allocation error\n");
	ret = 1;
	goto cleanup;
    }

    wbuffer = new unsigned char[DATA_BLOCK_SIZE]; // 256KB buffer size
    if (wbuffer == NULL) {
        printf("wbuffer allocation error\n");
	ret = 1;
	goto cleanup;
    }


    // open source and dest files
 
    srcfile = fopen(psource_file, "r");
    if (!srcfile) 
    {
        printf("fopen(%s) failed\n", psource_file);
        ret = 1;
        goto cleanup;
    }

    destfile = fopen(pdest_file, "w");
    if (!destfile)
    {
        printf("fopen(%s) failed\n", pdest_file);
        ret = 1;
        goto cleanup;
    }

	
    // init the descrypter
    result = initialize_encryptor(true);
    if (result != OE_OK)
    {
        ret = 1;
        goto cleanup;
    }

    // encrypt each block in the source file and write to the destfile
   while ((bread=fread(rbuffer, sizeof(unsigned char), DATA_BLOCK_SIZE, srcfile)) && bread > 0) 
    {
        memset(temp, 0, DATA_BLOCK_SIZE+1);
        memcpy(temp, rbuffer, bread);
        printf("--%s--\n", temp);
       
	result = crypt_block(rbuffer, wbuffer, bread);
        if (result != OE_OK)
        {
            ret = 1;
            goto cleanup;
        }
		
        if ((bwritten = fwrite(wbuffer, sizeof(unsigned char), bread, destfile)) != bread)
        {
            printf("fwrite errori %s\n", pdest_file);
            ret = 1;
            goto cleanup;
        }
        blockcount++;
        printf("blockcount =  %ld\n", blockcount);
    }

    // close files
   fclose(srcfile);
   fclose(destfile);

   close_encryptor();

cleanup:

     free(rbuffer);
     free(wbuffer);

    // terminate enclave
    oe_terminate_enclave(enclave);

    return ret;
}


