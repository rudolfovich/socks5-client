#include "socks5.h"

namespace proxy {

namespace socks5 {

ClientTcp::ClientTcp(const Ipv4Address& proxy_addr)
  : proxy_addr_(proxy_addr)
  , socket_(INVALID_SOCKET)
{
  const WORD requested_version = MAKEWORD(2, 2);
  WSADATA wsa_data = {};
  int err = WSAStartup(requested_version, &wsa_data);
  if (err != 0)
    throw ErrorSocksFailure(fmt("WSAStartup failed with error: ") << err);
  if (wsa_data.wVersion != requested_version) {
    WSACleanup();
    throw ErrorSocksFailure("Could not find a usable version of Winsock.dll");
  }
  socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_ == INVALID_SOCKET)
  {
    WSACleanup();
    throw ErrorSocksFailure("Could not find a usable version of Winsock.dll");
  }
}

ClientTcp::~ClientTcp()
{
  if (socket_ != INVALID_SOCKET) {
    closesocket(socket_);
    socket_ = INVALID_SOCKET;
  }
  WSACleanup();
}

void ClientTcp::Connect(const Ipv4Address& host, Ipv4Address& binded_addr)
{
  sockaddr_in addr      = {};
  addr.sin_family       = AF_INET;
  addr.sin_port         = htons(proxy_addr_.port);
  addr.sin_addr.s_addr  = htonl(proxy_addr_.addr);
  int ret = connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (ret == SOCKET_ERROR)
    throw ErrorSocksFailure(fmt("Could not connect to proxy server ") << proxy_addr_ << " failed: " << WSAGetLastError());
  {
    client::AuthRequest ca(AuthMethod_Unauthorized);
    Send(ca, ca.sendlen());
  }
  {
    server::AuthResponse sa;
    Recv(sa, sa.recvlen());
    if (! sa.validate())
      throw ErrorSocksFailure("Receive server::AuthResponse failed: Invalid data recieved.");
  }

  {
    client::Request req(Command_Connect, host);
    Send(req, req.sendlen());
  }

  {
    server::Response res;
    Recv(res, res.recvlen());
    if (! res.validate())
      throw ErrorSocksFailure("Receive server::Response failed: Invalid data recieved.");
    switch(res.address_type)
    {
      case AddressType_Ipv4:
      {
        Recv(res.bind_addr.ipv4);
        res.bind_addr.ipv4.addr = htonl(res.bind_addr.ipv4.addr);
        res.bind_addr.ipv4.port = htons(res.bind_addr.ipv4.port);
        binded_addr = res.bind_addr.ipv4;
        break;
      }
      case AddressType_Ipv6:
      {
        Recv(res.bind_addr.ipv6);
        //TODO:
        // res.bind_addr.ipv6.addr = htonl(res.bind_addr.ipv6.addr);
        // res.bind_addr.ipv6.port = htons(res.bind_addr.ipv6.port);
        break;
      }
      case AddressType_DomainName:
      {
        memset(res.bind_addr.domain.name, 0, sizeof(res.bind_addr.domain.name));

        Recv(res.bind_addr.domain.length);
        Recv(res.bind_addr.domain.name, res.bind_addr.domain.length);
        Recv(res.bind_addr.domain.port);
        res.bind_addr.domain.port = htons(res.bind_addr.domain.port);
        break;
      }
      default: throw ErrorGeneric(fmt("Unsupported address type: ") << res.address_type);
    }
  }
}

void ClientTcp::Disconnect()
{
  if (socket_ != INVALID_SOCKET) {
    closesocket(socket_);
    socket_ = INVALID_SOCKET;
  }
}

int ClientTcp::Recv(void* data, const size_t size)
{
  int len = static_cast<int>(size);
  char *buf = reinterpret_cast<char*>(data);
  int ret = recv(socket_, buf, len, 0);
  if (ret == SOCKET_ERROR)
    throw ErrorSocksFailure(fmt("Receive from proxy ") << proxy_addr_ << " failed: " << WSAGetLastError());
  return ret;
}

int ClientTcp::Send(const void* data, const size_t size)
{
  int len = static_cast<int>(size);
  const char *buf = reinterpret_cast<const char*>(data);
  do
  {
    int ret = send(socket_, buf, len, 0);
    if (ret == SOCKET_ERROR)
      throw ErrorSocksFailure(fmt("Send to proxy ") << proxy_addr_ << " failed: " << WSAGetLastError());
    len -= ret;
  }
  while(len > 0);
  return static_cast<int>(size);
}

}  // socks5

}  // proxy
