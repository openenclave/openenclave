#include "socket.h"

#include <stdint.h>
#include <cstring>
#include <iostream>
#include <thread>
#include <utility>

#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#define ABORT_WITH_ERROR(msg)                                                  \
    do                                                                         \
    {                                                                          \
        std::cout << "Abnormal exit from " << __FILE__ << "(" << __LINE__      \
                  << "): " << __PRETTY_FUNCTION__ << ": " << msg << std::endl; \
        exit(1);                                                               \
    } while (0)

void send(int32_t fd, const uint8_t* data, uint32_t length)
{
    while (length > 0)
    {
        int32_t b = write(fd, data, length);
        if (b < 0)
            ABORT_WITH_ERROR("socket write failure.");
        data += b;
        length -= b;
    }
}

void receive(int32_t fd, std::vector<uint8_t>& data)
{
    // Read all bytes from the client.
    int32_t length = 0;
    while (true)
    {
        int32_t nbytes = 10 * 1024;
        data.resize(data.size() + nbytes);
        nbytes = read(fd, &data[length], nbytes);
        if (nbytes < 0) {
            continue;
            ABORT_WITH_ERROR("Error reading from socket.");
        }

        length += nbytes;
        if (length < int32_t(data.size()))
        {
            // read complete.
            break;
        }
    }

    data.resize(length);
}

void defaultConnectionHandler(
    const std::string& requestorId,
    const std::string& request,
    const std::vector<uint8_t>& requestData,
    std::vector<uint8_t>& responseData)
{
    std::cout << "Received " << request << " [size= " << requestData.size()
              << "] from " << requestorId << std::endl;

    const char* msg = "Thanks!";
    responseData.insert(responseData.end(), msg, msg + 7);
}

struct SocketServerImpl
{
    int port;
    bool done;
    SocketServer::ConnectionHandler handler;
};

SocketServer::SocketServer(int port)
{
    impl = new SocketServerImpl{};
    impl->port = port;
    impl->handler = defaultConnectionHandler;
}

SocketServer::~SocketServer()
{
    delete impl;
}

void SocketServer::registerHandler(ConnectionHandler&& handler)
{
    impl->handler = std::move(handler);
}

void SocketServer::start()
{
    int32_t serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd == 0)
        ABORT_WITH_ERROR("socket creation error.");

    int32_t enable = 1;

    // Keep connections active and enable local address reuse.
    if ((setsockopt(
             serverfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) ==
         -1) ||
        (setsockopt(
             serverfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) ==
         -1))
        ABORT_WITH_ERROR("socket configuration error");

    sockaddr_in serverAddress = {};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(impl->port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverfd, (sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
        ABORT_WITH_ERROR("socket bind error");

    // Wait for connections. 5 backlog connections.
    if (listen(serverfd, 5) == -1)
        ABORT_WITH_ERROR("socket listen failure.");

    std::cout << "Server launched at"
              << ":" << impl->port << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(2));

    while (!impl->done)
    {
        sockaddr_in clientAddress;
        uint32_t clientAddressLength = sizeof(clientAddress);
        int clientfd =
            accept(serverfd, (sockaddr*)&clientAddress, &clientAddressLength);
        if (clientfd < 0)
            ABORT_WITH_ERROR("Client accept error.");

        std::thread([clientfd, this] {
            std::vector<uint8_t> requestData;
            std::vector<uint8_t> responseData;

            while (true)
            {
                requestData.clear();
                responseData.clear();
                receive(clientfd, requestData);

                // Check if connection was closed.
                if (requestData.empty())
                    break;

                // Parse requestor Id and request.
                auto itr = requestData.begin();
                while (itr != requestData.end() && *itr != '|')
                    ++itr;

                if (itr == requestData.end())
                    ABORT_WITH_ERROR("Malformed request.");

                std::string requestorId(requestData.begin(), itr++);
                itr = requestData.erase(requestData.begin(), itr);

                while (itr != requestData.end() && *itr != '|')
                    ++itr;

                if (itr == requestData.end())
                    ABORT_WITH_ERROR("Malformed request.");

                std::string request(requestData.begin(), itr++);
                itr = requestData.erase(requestData.begin(), itr);

                impl->handler(requestorId, request, requestData, responseData);
                if (!responseData.empty())
                    send(clientfd, &responseData[0], responseData.size());
                else
                    send(clientfd, (const uint8_t*)"", 0);
            }
        }).detach();
    }
}

void SocketServer::stop()
{
    impl->done = true;
}

struct SocketClientImpl
{
    std::string clientId;
    int32_t fd;
};

SocketClient::SocketClient(
    const std::string& clientId,
    const std::string& serverIpAddressAndPort)
{
    impl = new SocketClientImpl{};
    impl->clientId = clientId;

    size_t pos = serverIpAddressAndPort.rfind(':');
    std::string serverIpAddress = serverIpAddressAndPort.substr(0, pos);
    int port = atoi(serverIpAddressAndPort.substr(pos + 1).c_str());

    hostent* server = gethostbyname(serverIpAddress.c_str());
    if (server == NULL)
        ABORT_WITH_ERROR("server lookup error.");

    sockaddr_in serverAddress = {};
    serverAddress.sin_family = AF_INET;
    std::memcpy(
        &serverAddress.sin_addr.s_addr, server->h_addr, server->h_length);
    serverAddress.sin_port = htons(port);

    int32_t clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientfd < 0)
        ABORT_WITH_ERROR("socket creation error.");

    int32_t enable = 1;
    // Keep connections active and enable local address reuse.
    if ((setsockopt(
             clientfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) ==
         -1) ||
        (setsockopt(
             clientfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) ==
         -1))
        ABORT_WITH_ERROR("socket configuration error");

    int tries = 10;
    while (tries > 0)
    {
        if (connect(
                clientfd, (sockaddr*)&serverAddress, sizeof(serverAddress)) >=
            0)
            break;

        --tries;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    if (tries <= 0)
        ABORT_WITH_ERROR("Connection to server failed.");

    impl->fd = clientfd;
}

SocketClient::~SocketClient()
{
    close(impl->fd);
    delete impl;
}

void SocketClient::makeRequest(
    const std::string& request,
    const std::vector<uint8_t>& requestData,
    std::vector<uint8_t>& responseData)
{
    // Prepend requestorId and request string.
    std::vector<uint8_t> fullRequest(
        impl->clientId.begin(), impl->clientId.end());
    fullRequest.push_back('|');
    fullRequest.insert(fullRequest.end(), request.begin(), request.end());
    fullRequest.push_back('|');
    fullRequest.insert(
        fullRequest.end(), requestData.begin(), requestData.end());

    ::send(impl->fd, &fullRequest[0], fullRequest.size());
    ::receive(impl->fd, responseData);
}
