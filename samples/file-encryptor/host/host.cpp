// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include "../shared.h"

#include "fileencryptor_u.h"

using namespace std;

#define CIPHER_BLOCK_SIZE 16
#define DATA_BLOCK_SIZE 256
#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false

oe_enclave_t* enclave = NULL;

bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            cout << "Running in simulation mode" << endl;
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

// Dump Encryption header
void dump_header(encryption_header_t* _header)
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
int compare_2_files(const char* first_file, const char* second_file)
{
    int ret = 0;
    std::ifstream f1(first_file, std::ios::binary);
    std::ifstream f2(second_file, std::ios::binary);
    std::vector<uint8_t> f1_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f1), std::istreambuf_iterator<char>());
    std::vector<uint8_t> f2_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f2), std::istreambuf_iterator<char>());
    std::vector<uint8_t>::iterator f1iterator = f1_data_bytes.begin();
    std::vector<uint8_t>::iterator f2iterator = f2_data_bytes.begin();

    // compare files
    for (; f1iterator != f1_data_bytes.end() - 1; ++f1iterator, ++f2iterator)
    {
        if (!(*f1iterator == *f2iterator))
        {
            ret = 1;
            break;
        }
    }
    cout << "Host: two files are " << ((ret == 0) ? "equal" : "not equal")
         << endl;
    return ret;
}

int encrypt_file(
    bool encrypt,
    const char* password,
    const char* input_file,
    const char* output_file)
{
    oe_result_t result;
    int ret = 0;
    FILE* src_file = NULL;
    FILE* dest_file = NULL;
    unsigned char* r_buffer = NULL;
    unsigned char* w_buffer = NULL;
    size_t bytes_read;
    size_t bytes_written;
    size_t src_file_size = 0;
    size_t src_data_size = 0;
    size_t leftover_bytes = 0;
    size_t bytes_left = 0;
    size_t requested_read_size = 0;
    encryption_header_t header;

    // allocate read/write buffers
    r_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (r_buffer == NULL)
    {
        ret = 1;
        goto exit;
    }

    w_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (w_buffer == NULL)
    {
        cerr << "Host: w_buffer allocation error" << endl;
        ret = 1;
        goto exit;
    }

    // open source and dest files
    src_file = fopen(input_file, "rb");
    if (!src_file)
    {
        cout << "Host: fopen " << input_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    ret = get_file_size(src_file, &src_file_size);
    if (ret != 0)
    {
        ret = 1;
        goto exit;
    }
    src_data_size = src_file_size;
    dest_file = fopen(output_file, "wb");
    if (!dest_file)
    {
        cerr << "Host: fopen " << output_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    // For decryption, we want to read encryption header data into the header
    // structure before calling initialize_encryptor
    if (!encrypt)
    {
        bytes_read = fread(&header, 1, sizeof(header), src_file);
        if (bytes_read != sizeof(header))
        {
            cerr << "Host: read header failed." << endl;
            ret = 1;
            goto exit;
        }
        src_data_size = src_file_size - sizeof(header);
    }

    // Initialize the encryptor inside the enclave
    // Parameters: encrypt: a bool value to set the encryptor mode, true for
    // encryption and false for decryption
    // password is provided for encryption key used inside the encryptor. Upon
    // return, _header will be filled with encryption key information for
    // encryption operation. In the case of decryption, the caller provides
    // header information from a previously encrypted file
    result = initialize_encryptor(
        enclave, &ret, encrypt, password, strlen(password), &header);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }
    if (ret != 0)
    {
        goto exit;
    }

    // For encryption, on return from initialize_encryptor call, the header will
    // have encryption information. Write this header to the output file.
    if (encrypt)
    {
        header.file_data_size = src_file_size;
        bytes_written = fwrite(&header, 1, sizeof(header), dest_file);
        if (bytes_written != sizeof(header))
        {
            cerr << "Host: writting header failed. bytes_written = "
                 << bytes_written << " sizeof(header)=" << sizeof(header)
                 << endl;
            ret = 1;
            goto exit;
        }
    }

    leftover_bytes = src_data_size % CIPHER_BLOCK_SIZE;

    cout << "Host: leftover_bytes " << leftover_bytes << endl;

    // Encrypt each block in the source file and write to the dest_file. Process
    // all the blocks except the last one if its size is not a multiple of
    // CIPHER_BLOCK_SIZE when padding is needed
    bytes_left = src_data_size;

    if (leftover_bytes)
    {
        bytes_left = src_data_size - leftover_bytes;
    }
    requested_read_size = DATA_BLOCK_SIZE;
    cout << "Host: start " << (encrypt ? "encrypting" : "decrypting") << endl;

    // It loops through DATA_BLOCK_SIZE blocks one at a time then followed by
    // processing the last remaining multiple of CIPHER_BLOCK_SIZE blocks. This
    // loop makes sure all the data is processed except leftover_bytes bytes in
    // the end.
    while (
        (bytes_read = fread(
             r_buffer, sizeof(unsigned char), requested_read_size, src_file)) &&
        bytes_read > 0)
    {
        // Request for the enclave to encrypt or decrypt _input_buffer. The
        // block size (bytes_read), needs to be a multiple of CIPHER_BLOCK_SIZE.
        // In this sample, DATA_BLOCK_SIZE is used except the last block, which
        // will have to pad it to be a multiple of CIPHER_BLOCK_SIZE.
        result = encrypt_block(
            enclave, &ret, encrypt, r_buffer, w_buffer, bytes_read);
        if (result != OE_OK)
        {
            cerr << "encrypt_block error 1" << endl;
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            cerr << "encrypt_block error 1" << endl;
            goto exit;
        }

        if ((bytes_written = fwrite(
                 w_buffer, sizeof(unsigned char), bytes_read, dest_file)) !=
            bytes_read)
        {
            cerr << "Host: fwrite error  " << output_file << endl;
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

    if (encrypt)
    {
        // The CBC mode for AES assumes that we provide data in blocks of
        // CIPHER_BLOCK_SIZE bytes. This sample uses PKCS#5 padding. Pad the
        // whole CIPHER_BLOCK_SIZE block if leftover_bytes is zero. Pad the
        // (CIPHER_BLOCK_SIZE - leftover_bytes) bytes if leftover_bytes is
        // non-zero.
        size_t padded_byte_count = 0;
        unsigned char plaintext_padding_buf[CIPHER_BLOCK_SIZE];
        unsigned char ciphertext_padding_buf[CIPHER_BLOCK_SIZE];

        memset(ciphertext_padding_buf, 0, CIPHER_BLOCK_SIZE);
        memset(plaintext_padding_buf, 0, CIPHER_BLOCK_SIZE);

        if (leftover_bytes == 0)
            padded_byte_count = CIPHER_BLOCK_SIZE;
        else
            padded_byte_count = CIPHER_BLOCK_SIZE - leftover_bytes;

        cout << "Host: Working the last block" << endl;
        cout << "Host: padded_byte_count " << padded_byte_count << endl;
        cout << "Host: leftover_bytes " << leftover_bytes << endl;

        bytes_read = fread(
            plaintext_padding_buf,
            sizeof(unsigned char),
            leftover_bytes,
            src_file);
        if (bytes_read != leftover_bytes)
            goto exit;

        // PKCS5 Padding
        memset(
            (void*)(plaintext_padding_buf + leftover_bytes),
            padded_byte_count,
            padded_byte_count);

        result = encrypt_block(
            enclave,
            &ret,
            encrypt,
            plaintext_padding_buf,
            ciphertext_padding_buf,
            CIPHER_BLOCK_SIZE);
        if (result != OE_OK)
        {
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            goto exit;
        }

        bytes_written = fwrite(
            ciphertext_padding_buf,
            sizeof(unsigned char),
            CIPHER_BLOCK_SIZE,
            dest_file);
        if (bytes_written != CIPHER_BLOCK_SIZE)
            goto exit;
    }

    cout << "Host: done  " << (encrypt ? "encrypting" : "decrypting") << endl;

    // close files
    fclose(src_file);
    fclose(dest_file);

exit:
    delete[] r_buffer;
    delete[] w_buffer;
    cout << "Host: called close_encryptor" << endl;

    result = close_encryptor(enclave);
    if (result != OE_OK)
    {
        ret = 1;
    }
    return ret;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 0;
    const char* input_file = argv[1];
    const char* encrypted_file = "./out.encrypted";
    const char* decrypted_file = "./out.decrypted";
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    cout << "Host: enter main" << endl;
    if (argc != 3)
    {
        cerr << "Usage: " << argv[0]
             << " testfile enclave_image_path [ --simulate  ]" << endl;
        return 1;
    }

    cout << "Host: create enclave for image:" << argv[2] << endl;
    result = oe_create_fileencryptor_enclave(
        argv[2], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        cerr << "oe_create_fileencryptor_enclave() failed with " << argv[0]
             << " " << result << endl;
        ret = 1;
        goto exit;
    }

    // encrypt a file
    cout << "Host: encrypting file:" << input_file
         << " -> file:" << encrypted_file << endl;
    ret = encrypt_file(
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
    ret = compare_2_files(input_file, encrypted_file);
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

    ret = encrypt_file(
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
    ret = compare_2_files(input_file, decrypted_file);
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
