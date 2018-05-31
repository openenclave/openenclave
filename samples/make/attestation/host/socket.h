#ifndef OE_DEMO_SOCKET_H
#define OE_DEMO_SOCKET_H

#include <stdint.h>
#include <functional>
#include <string>
#include <vector>

struct SocketServerImpl;
struct SocketClientImpl;

class SocketServer
{
  public:
    explicit SocketServer(int port = 8000);
    ~SocketServer();

    void start();
    void stop();

    typedef std::function<void(
        const std::string& requestorId,
        const std::string& request,
        const std::vector<uint8_t>& requestData,
        std::vector<uint8_t>& responseData)>
        ConnectionHandler;

    void registerHandler(ConnectionHandler&& handler);

  private:
    // non copyable
    SocketServer(const SocketServer&) = delete;
    SocketServer& operator=(const SocketServer&) = delete;

  private:
    SocketServerImpl* impl;
};

class SocketClient
{
  public:
    SocketClient(
        const std::string& clientId,
        const std::string& serverIpAddressAndPort);
    ~SocketClient();

    void makeRequest(
        const std::string& request,
        const std::vector<uint8_t>& requestData,
        std::vector<uint8_t>& responseData);

  private:
    // non copyable
    SocketClient(const SocketClient&) = delete;
    SocketClient& operator=(const SocketClient&) = delete;

  private:
    SocketClientImpl* impl;
};

#endif // OE_DEMO_SOCKET_H
