// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/tests.h>
#include <openenclave/host.h>

#include <algorithm>
#include <cassert>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

#include <unistd.h>

#include "../args.h"
#include "socket.h"


std::string g_MyHostName;
std::string g_MyEnclaveId;
OE_Enclave* g_Enclave;

void enclaveRequestHandler(
    const std::string& requestingEnclaveId,
    const std::string& request,
    const std::vector<uint8_t>& requestData,
    std::vector<uint8_t>& responseData);

void performMutualAttestation(const std::string& remoteEnclaveId);

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    printf("==== %s\n", argv[0]);

    /* Check argument count */
    if (argc < 4)
    {
        print_usage:
            fprintf(
                stderr,
                "Usage: %s ENCLAVE_PATH -port:<port> -keep-alive:<seconds> "
                "[remote-enclave-host1:port] [remote-enclave-host2:port]...\n",
                argv[0]);
            return 1;
    }

    int port = 8000;
    int keepAlive = 0;
    for (int i = 2; i < 4; ++i)
    {
        const char* option = "-port:";
        int len = strlen(option);
        if (strncmp(argv[i], option, len) == 0)
        {
            sscanf(argv[i] + len, "%d", &port);
            continue;
        }

        option = "-keep-alive:";
        len = strlen(option);
        if (strncmp(argv[i], option, len) == 0)
        {
            sscanf(argv[i] + len, "%d", &keepAlive);
            continue;
        }

        fprintf(stderr, "Unknown option %s\n", argv[i]);
        goto print_usage;
    }

    char hostname[512] = {};
    gethostname(hostname, sizeof(hostname));

    g_MyHostName = hostname;
    g_MyHostName += ":" + std::to_string(port) + ":host";

    g_MyEnclaveId = hostname;
    g_MyEnclaveId += ":" + std::to_string(port);

    std::cout << g_MyHostName << ": keep-alive=" << keepAlive << std::endl;

    /* Create an enclave from the file given by argv[1] */
    {
        const uint64_t flags = OE_GetCreateFlags();

        if ((result = OE_CreateEnclave(
                 argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
        {
            std::cerr << g_MyHostName <<": OE_CreateEnclave(): result=" << result << std::endl;
            exit(1);
        }
    }

    
    g_Enclave = enclave;
    InitEnclaveArgs initArgs = {0};
    initArgs.enclaveId.bytes = (uint8_t*) &g_MyEnclaveId[0];
    initArgs.enclaveId.length = g_MyEnclaveId.size();
    if ((result = OE_CallEnclave(enclave, "InitializeEnclave", &initArgs)) != OE_OK) {
        std::cerr << g_MyHostName <<": InitializeEnclave failed(): result=" << result << std::endl;
        exit(1);
    }


    // Create server at specified port.
    SocketServer server(port);
    server.registerHandler(
        [enclave, port](
            const std::string& requestorId,
            const std::string& request,
            const std::vector<uint8_t>& requestData,
            std::vector<uint8_t>& responseData) {
            enclaveRequestHandler(requestorId, request, requestData, responseData);
        });

    // Launch the server in a separate thread.
    std::thread([&server] { server.start(); }).detach();

    // Pause for a second to let the server start.
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Launch keep-alive thread.
    std::thread([&server, keepAlive, port] {
        std::this_thread::sleep_for(std::chrono::seconds(keepAlive));
        server.stop();
        std::cout << g_MyHostName << ": Life-span elapsed. Host exiting." << std::endl;
        if (g_Enclave)
            OE_TerminateEnclave(g_Enclave);        
        g_Enclave = 0;
        exit(0);
    }).detach();

    // Read list of enclaves to perform mutual attestation with.
    std::string remoteEnclaveId;
    for (int i = 4; i < argc; ++i)
    {
        remoteEnclaveId = argv[i];
        if (!remoteEnclaveId.empty())
        {
            std::cout << g_MyHostName << ": Performing mutual-attestation with : "
                      << remoteEnclaveId << std::endl;
            performMutualAttestation(remoteEnclaveId);
        }
    }

    while (true)
    {
    }

    /* Terminate the enclave */
    if (g_Enclave)
        OE_TerminateEnclave(g_Enclave);
    g_Enclave = 0;

    return 0;
}

void enclaveRequestHandler(
    const std::string& requestingEnclaveId,
    const std::string& request,
    const std::vector<uint8_t>& requestData,
    std::vector<uint8_t>& responseData)
{
    if (request == "SendTextMessage")
    {
        std::cout<<std::endl<<std::endl<<std::endl;
        std::cout<<"*****************Sending Plain Text Message ***********************"<<std::endl;    

        std::cout << g_MyHostName << ": SendMessage requested by "
                  << requestingEnclaveId << std::endl;
        SendTextMessageArgs args = {};
        args.toEnclave.bytes = (uint8_t*)&requestingEnclaveId[0];
        args.toEnclave.length = requestingEnclaveId.size();

        args.result = OE_UNEXPECTED;
        if (OE_CallEnclave(g_Enclave, "SendTextMessage", &args) !=
                OE_OK ||
            args.result != OE_OK)
        {
            std::cerr << g_MyHostName << ": SendTextMessage failure." << std::endl;
            return;
        }

        responseData.insert(
            responseData.end(), (uint8_t*) args.message, (uint8_t*) args.message + sizeof(*args.message) + args.message->quoteSize);

        free(args.message);
        std::cout << g_MyHostName << ": Sending Text Message to " << requestingEnclaveId
                  << ". size = " << responseData.size() << " bytes. " << std::endl;

    } 
    else if(request == "SendPublicKeyMessage")
    {
        std::cout<<std::endl<<std::endl<<std::endl;
        std::cout<<"*****************Generating and Sending Public RSA Key ***********************"<<std::endl;    

        std::cout << g_MyHostName << ": SendPublicKeyMessage requested by "
                  << requestingEnclaveId << std::endl;
        SendPublicKeyMessageArgs args = {};
        args.toEnclave.bytes = (uint8_t*)&requestingEnclaveId[0];
        args.toEnclave.length = requestingEnclaveId.size();

        args.result = OE_UNEXPECTED;
        OE_CallEnclave(g_Enclave, "SendPublicKeyMessage", &args);
        if (args.result != OE_OK)
        {
            std::cerr << g_MyHostName << ": SendPublicKeyMessage failure." << std::endl;
            return;
        }

        responseData.insert(
            responseData.end(), (uint8_t*) args.message, (uint8_t*) args.message + sizeof(*args.message) + args.message->quoteSize);

        free(args.message);
        std::cout << g_MyHostName << ": Sending Public Key Message to " << requestingEnclaveId
                  << ". size = " << responseData.size() << " bytes. " << std::endl;
    }
    else if(request == "ReceiveEncryptedMessage")
    {
        std::cout<<std::endl<<std::endl<<std::endl;
        std::cout<<"*****************Received Encrypted Message ***********************"<<std::endl;   

        std::cout << g_MyHostName << ": ReceiveEncryptedMessage requested by "
                  << requestingEnclaveId << std::endl;
        ReceiveEncryptedMessageArgs args = {};
        args.fromEnclave.bytes = (uint8_t*)&requestingEnclaveId[0];
        args.fromEnclave.length = requestingEnclaveId.size();
        args.message = (EncryptedMessage*) &requestData[0];

        args.result = OE_UNEXPECTED;
        OE_CallEnclave(g_Enclave, "ReceiveEncryptedMessage", &args);
        if (args.result != OE_OK)
        {
            std::cerr << g_MyHostName << ": ReceiveEncryptedMessage failure." << std::endl;
            return;
        }

        responseData.insert(
            responseData.end(), (uint8_t*) args.message, (uint8_t*) args.message + sizeof(*args.message) + args.message->size);
    }    
}

void performMutualAttestation(const std::string& remoteEnclaveId)
{
    // Open a connection with the remote enclave.
    SocketClient client(g_MyEnclaveId, remoteEnclaveId);

    std::vector<uint8_t> requestData, responseData;


    // Request Plain text message.
    std::cout<<std::endl<<std::endl<<std::endl;
    std::cout<<"*****************Requesting Plain Text Message***********************"<<std::endl;
    
    client.makeRequest(
        "SendTextMessage", requestData, responseData);
    {
        std::cout<<std::endl<<std::endl<<std::endl;
        std::cout<<"*****************Received Text Message***********************"<<std::endl;

        PlainTextMessage* msg = (PlainTextMessage*) &responseData[0];
        ReceiveTextMessageArgs args = {};
        args.fromEnclave.bytes = (uint8_t*) &remoteEnclaveId[0];
        args.fromEnclave.length = remoteEnclaveId.size();
        args.message = msg;
       
        std::cout<<g_MyHostName<<": Received Text Message from " << remoteEnclaveId<<". size = " <<responseData.size()<<" bytes." << std::endl;
        if (OE_CallEnclave(g_Enclave, "ReceiveTextMessage", &args) != OE_OK ||
            args.result == OE_OK)
        {            
            std::cout << g_MyHostName << ": Validation of TextMessage from " << remoteEnclaveId
                      << " succeeded.\n";
        }
        else
        {
            
            std::cerr << g_MyHostName << ": Validation of TextMessage from " << remoteEnclaveId
                      << " failed.\n";
            return;
        }
    }
    
    requestData.clear();
    responseData.clear();        
    std::this_thread::sleep_for(std::chrono::seconds(8));

    std::cout<<std::endl<<std::endl<<std::endl;
    std::cout<<"*****************Requesting RSA Public Key***********************"<<std::endl;
        
    // Request public key.
    client.makeRequest(
        "SendPublicKeyMessage", requestData, responseData);    
    {
        std::cout<<std::endl<<std::endl<<std::endl;
        std::cout<<"*****************Received RSA Public Key***********************"<<std::endl;

        PublicKeyMessage* msg = (PublicKeyMessage*) &responseData[0];
        ReceivePublicKeyMessageArgs args = {};
        args.fromEnclave.bytes = (uint8_t*) &remoteEnclaveId[0];
        args.fromEnclave.length = remoteEnclaveId.size();
        args.message = msg;
       
        std::cout<<g_MyHostName<<": Received Public Key Message from " << remoteEnclaveId<<". size = " <<responseData.size()<<" bytes." << std::endl;
        if (OE_CallEnclave(g_Enclave, "ReceivePublicKeyMessage", &args) != OE_OK ||
            args.result == OE_OK)
        {            
            std::cout << g_MyHostName << ": Validation of Public Key from " << remoteEnclaveId
                      << " succeeded.\n";
        }
        else
        {
            
            std::cerr << g_MyHostName << ": Validation of Public Key from " << remoteEnclaveId
                      << " failed.\n";
            return;
        }
    }

    requestData.clear();
    responseData.clear();        
    std::this_thread::sleep_for(std::chrono::seconds(8));
    std::cout<<std::endl<<std::endl<<std::endl;
    std::cout<<"*****************Sending Encrypted Message using RSA ***********************"<<std::endl;

    // Generate Encrypted message
    {
        SendEncryptedMessageArgs args = {};
        args.toEnclave.bytes = (uint8_t*) &remoteEnclaveId[0];
        args.toEnclave.length = remoteEnclaveId.size();
        if (OE_CallEnclave(g_Enclave, "SendEncryptedMessage", &args) == OE_OK) {
            requestData.insert(requestData.end(), (uint8_t*) args.message, (uint8_t*) args.message + sizeof(*args.message) + args.message->size);

            std::cout<<g_MyHostName<<": Sending Encrypted Message to " << remoteEnclaveId<<". size = " <<requestData.size()<<" bytes." << std::endl;            
            client.makeRequest("ReceiveEncryptedMessage", requestData, responseData); 
            free (args.message);            
        } else {            
            std::cerr << g_MyHostName << ": SendEncryptedMessage to " << remoteEnclaveId
                      << " failed.\n";
            return;            
        }
    }   

    std::this_thread::sleep_for(std::chrono::seconds(3));
    std::cout<<std::endl<<std::endl<<std::endl;
    std::cout<<"*****************Done Sending Requests ***********************"<<std::endl;    
}
