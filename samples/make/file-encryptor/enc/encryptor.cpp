// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "encryptor.h"

//#include <openenclave/internal/hostalloc.h>


#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
//#include <stdlib.h>
#include <string.h>


#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>


#include "encryptor.h"

#define ENC_DEBUG_PRINTF(fmt, ...) \
    oe_host_printf("***%s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)


Encryptor::Encryptor()
{
    unsigned char iv[IV_SIZE] = {0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 
                                 0x5e, 0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75};
    memcpy(m_original_iv, iv, IV_SIZE);
}

void Encryptor::set_password(PasswordArgs* args)
{
   m_password = oe_host_strdup((const char*)args->password);
   if (m_password)
   {
      args->result = OE_OK;
   }
   else 
   {
       args->result = OE_OUT_OF_MEMORY;
   }
}

void Encryptor::initialize(EncryptArgs* args)
{
    int iret = 0;

    // initialize aes context
    mbedtls_aes_init(&m_aescontext);
    mbedtls_ctr_drbg_init(&m_ctldrbgcontext);
    mbedtls_entropy_init(&m_entropycontext);

    // generate encryption key
    generate_aes_key(m_password, m_encryption_key, ENCRYPTION_KEY_SIZE);

    // set aes key
    iret = mbedtls_aes_setkey_enc(&m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE); 
    if (iret != 0)
    {
	// print error here
        // exit
    }

    // init iv
    memcpy(m_operating_iv, m_original_iv, IV_SIZE);

    // ready for encryption


/*

	// If encrypting, call initialize to get the salt and IV.
	// If decrypting, we'll call this function later.
	if (encrypt) {
		rv = ew_crypt_initialize(1, salt, iv);
		if (rv != FC_OK) return rv;
	}
*/

}

void Encryptor::encryt_block(EncryptBlockArgs* args)
{
    //char *inputbuf = args->inputbuf;

    // The CBC mode for AES assumes that we provide data in blocks of 16 bytes. 
    // As we only have 40 bytes of data, we have to extend the input to contain 
    // 48 bytes of data instead. There are multiple ways to pad input data. The 
    // simplest is to just add zeroes to the end. This is only secure if we also
    // transmit the original length of the input data (40 in this case) securely 
    // to the other side as well. For this example we will use padding with zeroes.

    mbedtls_aes_crypt_cbc( &m_aescontext, 
                           MBEDTLS_AES_ENCRYPT, 
                           args->size, //input data length in bytes,  
                                       // must be a multiple of the block size (16 Bytes)
                           m_operating_iv,  //Initialization vector (updated after use)
                           args->inputbuf, 
                           args->outputbuf);

    //mbedtls_aes_crypt_cbc( &aes2, MBEDTLS_AES_DECRYPT, strlen((const char*)output), iv, output, output2 );

}

void Encryptor::close(CloseEncryptorArgs* args)
{
    if (m_password)
    {
        oe_host_free(m_password);
    }

    // clear aes context
    mbedtls_aes_free(&m_aescontext);
    mbedtls_entropy_free(&m_entropycontext);
    mbedtls_ctr_drbg_free(&m_ctldrbgcontext);
    ENC_DEBUG_PRINTF("Encryptor::close");
}

//Create AES key
//unsigned char key[32];

void Encryptor::generate_aes_key(char *_password, unsigned char *_key, unsigned int _length)
{

   mbedtls_ctr_drbg_context ctr_drbg;
   mbedtls_entropy_context entropy;
   char *pers = _password;
   int ret;

   mbedtls_entropy_init(&entropy);
   mbedtls_ctr_drbg_init(&ctr_drbg);

   if( ( ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (unsigned char *) pers, strlen(pers))) != 0)
   {
       ENC_DEBUG_PRINTF( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
       goto exit;
   }

   if ((ret = mbedtls_ctr_drbg_random( &ctr_drbg, _key, _length)) != 0)
   {
      ENC_DEBUG_PRINTF( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
      goto exit;
   }
 exit:
   return;
}

/*



mbedtls_aes_context aes;

unsigned char key[32];
unsigned char iv[16];

unsigned char input [128];
unsigned char output[128];

size_t input_len = 40;
size_t output_len = 0;


// Generating an AES key

// mbed TLS includes the CTR-DRBG module and an Entropy Collection module to
// help you with making an AES key generator for your key.


#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

//Create AES key
unsigned char key[32];

int generate_aes_key(char *password, unsigned char _key, unsigned int _length)
{

   mbedtls_ctr_drbg_context ctr_drbg;
   mbedtls_entropy_context entropy;
   char *pers = password;
   int ret;

   mbedtls_entropy_init( &entropy );
   mbedtls_ctr_drbg_init( &ctr_drbg );

   if( ( ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (unsigned char *) pers, strlen(pers))) != 0)
   {
       printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
       

goto exit;
   }

   if ((ret = mbedtls_ctr_drbg_random( &ctr_drbg, _key, _length)) != 0)
   {
      printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
      goto exit;
   }

  // key as a 256-bit AES key.
   return
}


#include "mbedtls/aes.h"

// Declare the variables needed for AES encryption


#include <openenclave/internal/random.h>





mbedtls_aes_context aes;

unsigned char key[32];
unsigned char iv[16];    // Initialization Vector (IV)

unsigned char input [128];
unsigned char output[128];

size_t input_len = 40;
size_t output_len = 0;

// fill iv with random data
oe_random(iv, 16); // check against OE_OK

// fill input with 40 bytes of input data and zeroized the rest of input.
memzero(input, 128);

mbedtls_aes_setkey_enc( &aes, key, 256 );

mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 24, iv, input, output );


init_encryption()
{
    // generate key

   // start encrypting
}




unsigned int ecrypto_set_password(wchar_t *pw)
{
  int rv = FC_OK;

        try {
                password.assign(pw);
        }
        catch (...)
        {
                rv = FC_ERR_UNKNOWN;
        }
        return rv;
}


// Cryptographic context

typedef struct crypto_context_struct {
        int encrypt;
        unsigned char key[16];
        unsigned char salt[16];
        unsigned char iv[12];
        unsigned char tag[16];
} crypto_context_t;


unsigned int ecrypto_crypt_initialize (int encrypt, unsigned char salt[16], unsigned char iv[12])
{
        sgx_status_t status;
        unsigned int rv= FC_OK;

        ctx.encrypt = encrypt;

        if (encrypt)
        {
            // fill iv with random data
            oe_random(iv, 16); // check against OE_OK
            // fill input with 40 bytes of input data and zeroized the rest of input.
            memzero(input, 128);
        }

        //derive an encryption key from the user's input password
        generate_aes_key(password, key, unsigned int _length);

        // set key
        mbedtls_aes_setkey_enc( &aes, key, 256 );

        return 0;
}

unsigned int ecrypto_crypt_block(unsigned char *inblock, unsigned char *outblock, size_t len)
{
        if (ctx.encrypt) return gcm128_encrypt(&ctx, inblock, outblock, len);
        return gcm128_decrypt(&ctx, inblock, outblock, len);
}

unsigned int ecrypto_crypt_finish(unsigned char tag[16])
{
        return gcm128_finish(&ctx, tag);
}

void ecrypto_crypt_close()
{
        gcm128_close(&ctx);
}



*/


/*
 

m_aescontext;

    mbedtls_aes_context aes2;

    unsigned char key[16] = "itzkbgulrcsjmnv";
    key[15] = 'x';

    unsigned char iv[16] = {0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 0x5e, 
                            0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75};

    const unsigned char *input = (const unsigned char*) "Some string to b";
    unsigned char output[128] = {0};
    unsigned char output2[128] = {0};

    mbedtls_aes_setkey_enc( &aes, key, 16*8 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, strlen((const char*)input), iv, input, output );

    mbedtls_aes_setkey_dec( &aes2, key, 16*8 );
    mbedtls_aes_crypt_cbc( &aes2, MBEDTLS_AES_DECRYPT, strlen((const char*)output), iv, output, output2 );
    
}
*/

