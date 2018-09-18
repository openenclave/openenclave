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
void dumpHeader(EncryptionHeader* _pHeader)
{
    cout << "--------- Dumping header -------------\n";
    cout << "Host: fileDataSize = " << _pHeader->fileDataSize << endl;

    cout << "Host: password digest:\n";
    for (int i = 0; i < HASH_VALUE_SIZE_IN_BYTES; i++)
    {
        cout << "Host: digest[" << i << "]" << std::hex
             << (unsigned int)(_pHeader->digest[i]) << endl;
    }

    cout << "Host: encryption key" << endl;
    for (int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
    {
        cout << "Host: key[" << i << "]=" << std::hex
             << (unsigned int)(_pHeader->encryptedKey[i]) << endl;
    }
}

// get the file size
int getFileSize(FILE* file, size_t* _fileSize)
{
    int ret = 0;
    long int oldpos = 0;

    oldpos = ftell(file);
    ret = fseek(file, 0L, SEEK_END);
    if (ret != 0)
        goto exit;

    *_fileSize = (size_t)ftell(file);
    fseek(file, oldpos, SEEK_SET);
exit:
    return ret;
}

// Compare file1 and file2: return 0 if the first file1.size bytes of the file2
// is equal to file1's contents  Otherwise it returns 1
int compareTwoFiles(const char* firstFile, const char* secondFile)
{
    int ret = 0;
    std::ifstream f1(firstFile, std::ios::binary);
    std::ifstream f2(secondFile, std::ios::binary);
    std::vector<uint8_t> f1DataBytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f1), std::istreambuf_iterator<char>());
    std::vector<uint8_t> f2DataBytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f2), std::istreambuf_iterator<char>());
    auto f1iterator = f1DataBytes.begin();
    auto f2iterator = f2DataBytes.begin();

    // compare files
    for (; f1iterator != f1DataBytes.end() - 1; ++f1iterator, ++f2iterator)
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
// Parameters: bEncrypt: a bool value to set the encryptor mode, true for
// encryption and false for decryption
// password is provided for encryption key used inside the encryptor. Upon
// return, _header will be filled with encryption key information for encryption
// operation. In the case of decryption, the caller provides header information
// from a previously encrypted file
oe_result_t InitializeEncryptor(
    bool bEncrypt,
    EncryptionHeader* _header,
    const char* password)
{
    EncryptInitializeArgs arg = {0};
    oe_result_t result = OE_OK;
    arg.bEncrypt = bEncrypt;
    arg.password = password;
    arg.pHeader = _header;

    result = oe_call_enclave(enclave, "InitializeEncryptor", (void*)&arg);
    if (result != OE_OK)
    {
        cerr << "Host: InitializeEncryptor failed:" << result << endl;
        goto exit;
    }
    memcpy(_header, arg.pHeader, sizeof(EncryptionHeader));

exit:
    return result;
}

// Request for the enclave to encrypt or decrypt _inputBuffer. The input data
// size, _size, needs to be a multiple of CIPHER_BLOCK_SIZE. In this sample,
// DATA_BLOCK_SIZE is used except the last block, which will have to pad it to
// be a multiple of CIPHER_BLOCK_SIZE.
oe_result_t EncryptBlock(
    bool _bEncrypt,
    unsigned char* _inputBuffer,
    unsigned char* _outputBuffer,
    size_t _size)
{
    EncryptBlockArgs arg;
    oe_result_t result = OE_OK;
    arg.bEncrypt = _bEncrypt;
    arg.inputbuf = _inputBuffer;
    arg.outputbuf = _outputBuffer;
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
    arg.bEncrypt = true;

    result = oe_call_enclave(enclave, "CloseEncryptor", (void*)&arg);
    if (result != OE_OK)
    {
        cerr << "Host: initialize_encryption failed:" << result << endl;
    }
    return result;
}

int EncryptFile(
    bool _bEncrypt,
    const char* _password,
    const char* _inputFile,
    const char* _outputFile)
{
    oe_result_t result;
    int ret = 0;
    FILE* srcFile = NULL;
    FILE* destFile = NULL;
    unsigned char* readBuffer = NULL;
    unsigned char* writeBuffer = NULL;
    size_t bytesRead;
    size_t bytesWritten;
    size_t srcfilesize = 0;
    size_t srcDataSize = 0;
    size_t leftoverbytes = 0;
    size_t bytesLeft = 0;
    size_t requestedReadSize = 0;
    EncryptionHeader header;

    // allocate read/write buffers
    readBuffer = new unsigned char[DATA_BLOCK_SIZE];
    if (readBuffer == NULL)
    {
        ret = 1;
        goto exit;
    }

    writeBuffer = new unsigned char[DATA_BLOCK_SIZE];
    if (writeBuffer == NULL)
    {
        cerr << "Host: writeBuffer allocation error" << endl;
        ret = 1;
        goto exit;
    }

    // open source and dest files
    srcFile = fopen(_inputFile, "r");
    if (!srcFile)
    {
        cout << "Host: fopen " << _inputFile << " failed." << endl;
        ret = 1;
        goto exit;
    }

    ret = getFileSize(srcFile, &srcfilesize);
    if (ret != 0)
    {
        ret = 1;
        goto exit;
    }
    srcDataSize = srcfilesize;
    destFile = fopen(_outputFile, "w");
    if (!destFile)
    {
        cerr << "Host: fopen " << _outputFile << " failed." << endl;
        ret = 1;
        goto exit;
    }

    // For decryption, we want to read encryption header data into the header
    // structure before calling InitializeEncryptor
    if (!_bEncrypt)
    {
        bytesRead = fread(&header, 1, sizeof(header), srcFile);
        if (bytesRead != sizeof(header))
        {
            cerr << "Host: read header failed." << endl;
            ret = 1;
            goto exit;
        }
        srcDataSize = srcfilesize - sizeof(header);
    }

    result = InitializeEncryptor(_bEncrypt, &header, _password);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }

    // For encryption, on return from InitializeEncryptor call, the header will
    // have encryption information. Write this header to the output file.
    if (_bEncrypt)
    {
        header.fileDataSize = srcfilesize;
        bytesWritten = fwrite(&header, 1, sizeof(header), destFile);
        if (bytesWritten != sizeof(header))
        {
            cerr << "Host: writting header failed. bytesWritten = "
                 << bytesWritten << " sizeof(header)=" << sizeof(header)
                 << endl;
            ret = 1;
            goto exit;
        }
    }

    leftoverbytes = srcDataSize % CIPHER_BLOCK_SIZE;

    // Encrypt each block in the source file and write to the destFile. Process
    // all the blocks except the last one if its size is not a multiple of
    // CIPHER_BLOCK_SIZE
    bytesLeft = srcDataSize;
    if (leftoverbytes)
    {
        bytesLeft = srcDataSize - leftoverbytes;
    }
    requestedReadSize = DATA_BLOCK_SIZE;
    cout << "Host: start " << (_bEncrypt ? "encrypting" : "decrypting") << endl;
    while (
        (bytesRead = fread(
             readBuffer, sizeof(unsigned char), requestedReadSize, srcFile)) &&
        bytesRead > 0)
    {
        result = EncryptBlock(_bEncrypt, readBuffer, writeBuffer, bytesRead);
        if (result != OE_OK)
        {
            ret = 1;
            goto exit;
        }

        if ((bytesWritten = fwrite(
                 writeBuffer, sizeof(unsigned char), bytesRead, destFile)) !=
            bytesRead)
        {
            cerr << "Host: fwrite error  " << _outputFile << endl;
            ret = 1;
            goto exit;
        }
        bytesLeft -= requestedReadSize;
        if (bytesLeft == 0)
            break;
        if (bytesLeft < DATA_BLOCK_SIZE)
        {
            requestedReadSize = bytesLeft;
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
        if (_bEncrypt)
        {
            bytesRead = fread(
                paddingtest, sizeof(unsigned char), leftoverbytes, srcFile);
            if (bytesRead != leftoverbytes)
                goto exit;

            // PKCS5 Padding
            for (int i = leftoverbytes; i < CIPHER_BLOCK_SIZE; i++)
            {
                paddingtest[i] = CIPHER_BLOCK_SIZE - leftoverbytes;
            }

            result = EncryptBlock(
                _bEncrypt,
                paddingtest,
                paddingtest_ciphertext,
                CIPHER_BLOCK_SIZE);
            if (result != OE_OK)
                goto exit;

            bytesWritten = fwrite(
                paddingtest_ciphertext,
                sizeof(unsigned char),
                CIPHER_BLOCK_SIZE,
                destFile);
            if (bytesWritten != CIPHER_BLOCK_SIZE)
                goto exit;
        }
        else
        {
            bytesRead = fread(
                paddingtest_ciphertext,
                sizeof(unsigned char),
                CIPHER_BLOCK_SIZE,
                srcFile);
            if (bytesRead != CIPHER_BLOCK_SIZE)
                goto exit;

            result = EncryptBlock(
                _bEncrypt,
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
            bytesWritten = fwrite(
                paddingtest, sizeof(unsigned char), leftoverbytes, destFile);
            if (bytesWritten != leftoverbytes)
                goto exit;
        }
    }

    cout << "Host: done  " << (_bEncrypt ? "encrypting" : "decrypting") << endl;

    // close files
    fclose(srcFile);
    fclose(destFile);

exit:
    free(readBuffer);
    free(writeBuffer);
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
    ret = compareTwoFiles(input_file, encrypted_file);
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
    ret = compareTwoFiles(input_file, decrypted_file);
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
