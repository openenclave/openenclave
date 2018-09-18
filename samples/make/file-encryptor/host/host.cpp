// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <iostream>
#include <iterator>
#include <vector>
#include "../args.h"

using namespace std;

#define CIPHER_BLOCK_SIZE 16
#define DATA_BLOCK_SIZE 256
#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false

oe_enclave_t* enclave = NULL;

// Dump Encryption header
void dump_header(EncryptionHeader* _header)
{
    cout << "--------- Dumping header -------------\n";
    cout << "Host: fileDataSize = " << _header->file_data_size << endl;

    cout << "Host: password digest:\n";
    for (int i = 0; i < HASH_VALUE_SIZE_IN_BYTES; i++)
    {
        cout << "Host: digest[" << i << "]" << std::hex
             << (unsigned int)(_header->digest[i]) << endl;
    }

    cout << "Host: encryption key" << endl;
    for (int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
    {
        cout << "Host: key[" << i << "]=" << std::hex
             << (unsigned int)(_header->encrypted_key[i]) << endl;
    }
}

// get the file size
int get_file_size(FILE* file, size_t* _file_size)
{
    int ret = 0;
    long int oldpos = 0;

    oldpos = ftell(file);
    ret = fseek(file, 0L, SEEK_END);
    if (ret != 0)
        goto exit;

    *_file_size = (size_t)ftell(file);
    fseek(file, oldpos, SEEK_SET);
exit:
    return ret;
}

// Compare file1 and file2: return 0 if the first file1.size bytes of the file2
// is equal to file1's contents  Otherwise it returns 1
int compare_two_files(const char* first_file, const char* second_file)
{
    int ret = 0;
    std::ifstream f1(first_file, std::ios::binary);
    std::ifstream f2(second_file, std::ios::binary);
    std::vector<uint8_t> f1_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f1), std::istreambuf_iterator<char>());
    std::vector<uint8_t> f2_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f2), std::istreambuf_iterator<char>());
    auto f1iterator = f1_data_bytes.begin();
    auto f2iterator = f2_data_bytes.begin();

    // compare files
    for (; f1iterator != f1_data_bytes.end() - 1; ++f1iterator, ++f2iterator)
    {
        if (!(*f1iterator == *f2iterator))
        {
            ret = 1;
            break;
        }
    }
    cout << "Two files are " << ((ret == 0) ? "equal" : "not equal") << endl;
    return ret;
}

// Initialize the encryptor inside the enclave
// Parameters: do_encrypt: a bool value to set the encryptor mode, true for
// encryption and false for decryption
// password is provided for encryption key used inside the encryptor. Upon
// return, _header will be filled with encryption key information for encryption
// operation. In the case of decryption, the caller provides header information
// from a previously encrypted file
oe_result_t InitializeEncryptor(
    bool do_encrypt,
    EncryptionHeader* _header,
    const char* password)
{
    EncryptInitializeArgs arg = {0};
    oe_result_t result = OE_OK;
    arg.do_encrypt = do_encrypt;
    arg.password = password;
    arg.header = _header;

    result = oe_call_enclave(enclave, "InitializeEncryptor", (void*)&arg);
    if (result != OE_OK)
    {
        cerr << "Host: InitializeEncryptor failed:" << result << endl;
        goto exit;
    }
    memcpy(_header, arg.header, sizeof(EncryptionHeader));

exit:
    return result;
}

// Request for the enclave to encrypt or decrypt _input_buffer. The input data
// size, _size, needs to be a multiple of CIPHER_BLOCK_SIZE. In this sample,
// DATA_BLOCK_SIZE is used except the last block, which will have to pad it to
// be a multiple of CIPHER_BLOCK_SIZE.
oe_result_t EncryptBlock(
    bool _do_encrypt,
    unsigned char* _input_buffer,
    unsigned char* _output_buffer,
    size_t _size)
{
    EncryptBlockArgs arg;
    oe_result_t result = OE_OK;
    arg.do_encrypt = _do_encrypt;
    arg.inputbuf = _input_buffer;
    arg.outputbuf = _output_buffer;
    arg.size = _size;

    result = oe_call_enclave(enclave, "EncryptBlock", (void*)&arg);
    if (result != OE_OK)
    {
        cerr << "Host: EncryptBlock failed :" << result << endl;
    }
    return result;
}

// Free the resource used by the encryptor instance
oe_result_t CloseEncryptor()
{
    CloseEncryptorArgs arg = {0};
    oe_result_t result;
    arg.do_encrypt = true;

    result = oe_call_enclave(enclave, "CloseEncryptor", (void*)&arg);
    if (result != OE_OK)
    {
        cerr << "Host: initialize_encryption failed:" << result << endl;
    }
    return result;
}

int EncryptFile(
    bool _do_encrypt,
    const char* _password,
    const char* _input_file,
    const char* _output_file)
{
    oe_result_t result;
    int ret = 0;
    FILE* src_file = NULL;
    FILE* dest_file = NULL;
    unsigned char* read_buffer = NULL;
    unsigned char* write_buffer = NULL;
    size_t bytes_read;
    size_t bytes_written;
    size_t srcfilesize = 0;
    size_t src_data_size = 0;
    size_t leftoverbytes = 0;
    size_t bytes_left = 0;
    size_t requested_read_size = 0;
    EncryptionHeader header;

    // allocate read/write buffers
    read_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (read_buffer == NULL)
    {
        ret = 1;
        goto exit;
    }

    write_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (write_buffer == NULL)
    {
        cerr << "Host: writeBuffer allocation error" << endl;
        ret = 1;
        goto exit;
    }

    // open source and dest files
    src_file = fopen(_input_file, "r");
    if (!src_file)
    {
        cout << "Host: fopen " << _input_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    ret = get_file_size(src_file, &srcfilesize);
    if (ret != 0)
    {
        ret = 1;
        goto exit;
    }
    src_data_size = srcfilesize;
    dest_file = fopen(_output_file, "w");
    if (!dest_file)
    {
        cerr << "Host: fopen " << _output_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    // For decryption, we want to read encryption header data into the header
    // structure before calling InitializeEncryptor
    if (!_do_encrypt)
    {
        bytes_read = fread(&header, 1, sizeof(header), src_file);
        if (bytes_read != sizeof(header))
        {
            cerr << "Host: read header failed." << endl;
            ret = 1;
            goto exit;
        }
        src_data_size = srcfilesize - sizeof(header);
    }

    result = InitializeEncryptor(_do_encrypt, &header, _password);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }

    // For encryption, on return from InitializeEncryptor call, the header will
    // have encryption information. Write this header to the output file.
    if (_do_encrypt)
    {
        header.file_data_size = srcfilesize;
        bytes_written = fwrite(&header, 1, sizeof(header), dest_file);
        if (bytes_written != sizeof(header))
        {
            cerr << "Host: writting header failed. bytesWritten = "
                 << bytes_written << " sizeof(header)=" << sizeof(header)
                 << endl;
            ret = 1;
            goto exit;
        }
    }

    leftoverbytes = src_data_size % CIPHER_BLOCK_SIZE;

    // Encrypt each block in the source file and write to the dest_file. Process
    // all the blocks except the last one if its size is not a multiple of
    // CIPHER_BLOCK_SIZE
    bytes_left = src_data_size;
    if (leftoverbytes)
    {
        bytes_left = src_data_size - leftoverbytes;
    }
    requested_read_size = DATA_BLOCK_SIZE;
    cout << "Host: start " << (_do_encrypt ? "encrypting" : "decrypting") << endl;
    while (
        (bytes_read = fread(
             read_buffer, sizeof(unsigned char), requested_read_size, src_file)) &&
        bytes_read > 0)
    {
        result = EncryptBlock(_do_encrypt, read_buffer, write_buffer, bytes_read);
        if (result != OE_OK)
        {
            ret = 1;
            goto exit;
        }

        if ((bytes_written = fwrite(
                 write_buffer, sizeof(unsigned char), bytes_read, dest_file)) !=
            bytes_read)
        {
            cerr << "Host: fwrite error  " << _output_file << endl;
            ret = 1;
            goto exit;
        }
        bytes_left -= requested_read_size;
        if (bytes_left == 0)
            break;
        if (bytes_left < DATA_BLOCK_SIZE)
        {
            requested_read_size = bytes_left;
        }
    }

    // The CBC mode for AES assumes that we provide data in blocks of
    // CIPHER_BLOCK_SIZE bytes. If the file size is not a multiple of
    // CIPHER_BLOCK_SIZE-byte blocks, PKCS5 Padding was used to make it exactly
    // a CIPHER_BLOCK_SIZE-byte block
    if (leftoverbytes)
    {
        unsigned char paddingtest[CIPHER_BLOCK_SIZE];
        unsigned char paddingtest_ciphertext[CIPHER_BLOCK_SIZE];
        cout << "Host: Working the last block" << endl;
        cout << "Host: Input file size if not multiples of "
             << CIPHER_BLOCK_SIZE << "-byte blocks "
             << "(leftoverbytes = " << leftoverbytes << endl;

        memset(paddingtest_ciphertext, 0, CIPHER_BLOCK_SIZE);
        memset(paddingtest, 0, CIPHER_BLOCK_SIZE);
        if (_do_encrypt)
        {
            bytes_read = fread(
                paddingtest, sizeof(unsigned char), leftoverbytes, src_file);
            if (bytes_read != leftoverbytes)
                goto exit;

            // PKCS5 Padding
            for (int i = leftoverbytes; i < CIPHER_BLOCK_SIZE; i++)
            {
                paddingtest[i] = CIPHER_BLOCK_SIZE - leftoverbytes;
            }

            result = EncryptBlock(
                _do_encrypt,
                paddingtest,
                paddingtest_ciphertext,
                CIPHER_BLOCK_SIZE);
            if (result != OE_OK)
                goto exit;

            bytes_written = fwrite(
                paddingtest_ciphertext,
                sizeof(unsigned char),
                CIPHER_BLOCK_SIZE,
                dest_file);
            if (bytes_written != CIPHER_BLOCK_SIZE)
                goto exit;
        }
        else
        {
            bytes_read = fread(
                paddingtest_ciphertext,
                sizeof(unsigned char),
                CIPHER_BLOCK_SIZE,
                src_file);
            if (bytes_read != CIPHER_BLOCK_SIZE)
                goto exit;

            result = EncryptBlock(
                _do_encrypt,
                paddingtest_ciphertext,
                paddingtest,
                CIPHER_BLOCK_SIZE);
            if (result != OE_OK)
                goto exit;

            // validating decrypted message's PKCS5 Padding
            for (int i = leftoverbytes; i < CIPHER_BLOCK_SIZE; i++)
            {
                if (paddingtest[i] != (CIPHER_BLOCK_SIZE - leftoverbytes))
                {
                    cout << "PKCS5 Padding validation failed: "
                         << (unsigned int)paddingtest[i] << " vs "
                         << (unsigned int)(CIPHER_BLOCK_SIZE - leftoverbytes)
                         << endl;
                    if (paddingtest[i] != (CIPHER_BLOCK_SIZE - leftoverbytes))
                        goto exit;
                }
            }
            bytes_written = fwrite(
                paddingtest, sizeof(unsigned char), leftoverbytes, dest_file);
            if (bytes_written != leftoverbytes)
                goto exit;
        }
    }

    cout << "Host: done  " << (_do_encrypt ? "encrypting" : "decrypting") << endl;

    // close files
    fclose(src_file);
    fclose(dest_file);

exit:
    free(read_buffer);
    free(write_buffer);
    cout << "Host: called CloseEncryptor" << endl;
    CloseEncryptor();
    return ret;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 0;
    const char* input_file = argv[1];
    const char* encrypted_file = "./out.encrypted";
    const char* decrypted_file = "./out.decrypted";

    cout << "Host: enter main" << endl;
    if (argc != 3)
    {
        cerr << "Usage: " << argv[0] << " source_file_name ENCLAVE_PATH"
             << endl;
        return 1;
    }

    cout << "Host: create enclave for image:" << argv[2] << endl;
    result = oe_create_enclave(
        argv[2], OE_ENCLAVE_TYPE_SGX, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        cerr << "oe_create_enclave() failed with " << argv[0] << " " << result
             << endl;
        ret = 1;
        goto exit;
    }

    // encrypt a file
    cout << "Host: encrypting file:" << input_file
         << " -> file:" << encrypted_file << endl;
    ret = EncryptFile(
        ENCRYPT_OPERATION, "anyPasswordYouLike", input_file, encrypted_file);
    if (ret != 0)
    {
        cerr << "Host: processFile(ENCRYPT_OPERATION) failed with " << ret
             << endl;
        goto exit;
    }

    // Make sure the encryption was doing something. Input and encrypted files
    // are not equal
    cout << "Host: compared file:" << encrypted_file
         << " to file:" << decrypted_file << endl;
    ret = compare_two_files(input_file, encrypted_file);
    if (ret == 0)
    {
        cerr << "Host: checking failed! " << input_file
             << "'s contents are not supposed to be same as " << encrypted_file
             << endl;
        goto exit;
    }
    cout << "Host: " << input_file << " is NOT equal to " << decrypted_file
         << "as expected" << endl;
    cout << "Host: encryption was done successfully" << endl;

    // Decrypt a file
    cout << "Host: decrypting file:" << encrypted_file
         << " to file:" << decrypted_file << endl;

    ret = EncryptFile(
        DECRYPT_OPERATION,
        "anyPasswordYouLike",
        encrypted_file,
        decrypted_file);
    if (ret != 0)
    {
        cerr << "Host: processFile(DECRYPT_OPERATION) failed with " << ret
             << endl;
        goto exit;
    }
    cout << "Host: compared file:" << encrypted_file
         << " to file:" << decrypted_file << endl;
    ret = compare_two_files(input_file, decrypted_file);
    if (ret != 0)
    {
        cerr << "Host: checking failed! " << input_file
             << "'s is supposed to be same as " << decrypted_file << endl;
        goto exit;
    }
    cout << "Host: " << input_file << " is equal to " << decrypted_file << endl;

exit:
    cout << "Host: terminate the enclave" << endl;
    cout << "Host: Sample completed successfully." << endl;
    oe_terminate_enclave(enclave);
    return ret;
}
