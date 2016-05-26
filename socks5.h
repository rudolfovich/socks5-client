#pragma once

#define STRICT
#include <cstdint>
#include <stdexcept>
#include <sstream>
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#pragma comment( lib, "Ws2_32.lib")


namespace proxy {
namespace socks5 {

struct Ipv4Address;

typedef std::string   string;
typedef const string  cstring;

Ipv4Address Ipv4(uint32_t _addr, uint16_t _port);
Ipv4Address Ipv4(uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4, uint16_t _port);

//
// SOCKS5 Exceptions
//
class ErrorGeneric                  : public std::runtime_error { public: ErrorGeneric(cstring& msg) : std::runtime_error(msg) {} };
class ErrorNetworkFailure           : public ErrorGeneric       { public: ErrorNetworkFailure(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorSocksFailure             : public ErrorGeneric       { public: ErrorSocksFailure(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorNotAllowed               : public ErrorGeneric       { public: ErrorNotAllowed(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorNetUnreachable           : public ErrorGeneric       { public: ErrorNetUnreachable(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorHostUnreachable          : public ErrorGeneric       { public: ErrorHostUnreachable(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorConnRefused              : public ErrorGeneric       { public: ErrorConnRefused(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorTtlExpired               : public ErrorGeneric       { public: ErrorTtlExpired(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorUnsupportedCommand       : public ErrorGeneric       { public: ErrorUnsupportedCommand(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorUnsupportedAddrType      : public ErrorGeneric       { public: ErrorUnsupportedAddrType(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorNoAcceptableMethodsFound : public ErrorGeneric       { public: ErrorNoAcceptableMethodsFound(cstring& msg) : ErrorGeneric(msg) {}  };

}  // socks5
}  // proxy


#pragma pack(push, 1)

namespace proxy {
namespace socks5 {
//
// https://tools.ietf.org/html/rfc1928
//
struct Ipv4Address
{
  union
  {
    uint32_t    addr;
    uint8_t     parts[4];
    struct
    {
      uint8_t   part4;
      uint8_t   part3;
      uint8_t   part2;
      uint8_t   part1;
    };
  };
  uint16_t      port;
};

struct Ipv6Address
{
  union
  {
    uint16_t    parts[8];
    struct
    {
      uint16_t  part8;
      uint16_t  part7;
      uint16_t  part6;
      uint16_t  part5;
      uint16_t  part4;
      uint16_t  part3;
      uint16_t  part2;
      uint16_t  part1;
    };
  };
  uint16_t      port;
};

struct DomainName
{
  uint8_t       length;
  uint8_t       name[255];
  uint16_t      port;
};


///
/// \brief The SOCKS5 Tcp Client class
///
class ClientTcp
{
  SOCKET socket_;

public:
  ClientTcp();
  ~ClientTcp();

  void Connect(const Ipv4Address& proxy, const Ipv4Address& host, Ipv4Address& binded);
  void Disconnect();

  int Recv(void *data, size_t size);
  int Send(const void *data, size_t size);

  int Recv(string& data);
  int Send(const string& data);

  template<typename T> int Recv(T& data);
  template<typename T> int Send(const T& data);
};



enum Version : uint8_t
{
  Version_Undefined = 0x00,  // '00' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
  Version_5         = 0x05,  // '05' Socks5 Protocol Version
};

static const Version kSocksVersion = Version_5;

enum AuthMethod : uint8_t
{
  // The values currently defined for METHOD are:
  AuthMethod_Unauthorized        = 0x00, // '00' NO AUTHENTICATION REQUIRED
  AuthMethod_GssApi              = 0x01, // '01' GSSAPI
  AuthMethod_UsernamePassword    = 0x02, // '02' USERNAME/PASSWORD
                                         // '03' to X'7F' IANA ASSIGNED
                                         // '80' to X'FE' RESERVED FOR PRIVATE METHODS
  AuthMethod_Undefined           = 0xfe, // 'FF' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
  AuthMethod_NoAcceptableMethods = 0xff, // 'FF' NO ACCEPTABLE METHODS
};

enum Command : uint8_t
{
  Command_Undefined    = 0x00, // '00' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
  Command_Connect      = 0x01, // '01' CONNECT
  Command_Bind         = 0x02, // '02' BIND
  Command_UdpAssociate = 0x03, // '03' UDP ASSOCIATE
};

enum AddressType : uint8_t
{
  AddressType_Undefined  = 0x00, // '00' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
  AddressType_Ipv4       = 0x01, // '01' IP V4 address
  AddressType_DomainName = 0x03, // '03' DOMAINNAME
  AddressType_Ipv6       = 0x04, // '04' IP V6 address
};

enum ReplyType : uint8_t
{
  ReplyType_Succeeded           = 0x00, // '00' succeeded
  ReplyType_SocksFailure        = 0x01, // '01' general SOCKS server failure
  ReplyType_NotAllowed          = 0x02, // '02' connection not allowed by ruleset
  ReplyType_NetUnreachable      = 0x03, // '03' Network unreachable
  ReplyType_HostUnreachable     = 0x04, // '04' Host unreachable
  ReplyType_ConnRefused         = 0x05, // '05' Connection refused
  ReplyType_TtlExpired          = 0x06, // '06' TTL expired
  ReplyType_UnsupportedCommand  = 0x07, // '07' Command not supported
  ReplyType_UnsupportedAddrType = 0x08, // '08' Address type not supported
                                        // '09' to X'FF' unassigned
  ReplyType_Undefined           = 0xFF, // 'FF' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
};

#ifndef NO_TYPED_ENUMS
typedef Version       VersionField;
typedef AuthMethod    AuthMethodField;
typedef Command       CommandField;
typedef AddressType   AddressTypeField;
typedef ReplyType     ReplyTypeField;
#else
typedef uint8_t       VersionField;
typedef uint8_t       AuthMethodField;
typedef uint8_t       CommandField;
typedef uint8_t       AddressTypeField;
typedef uint8_t       ReplyTypeField;

#endif


namespace client {

struct AuthRequest
{
  VersionField      version;
  uint8_t           auth_method_count;
  AuthMethodField   auth_methods[255];

  AuthRequest(AuthMethod method);

  operator const char*() const { return reinterpret_cast<const char *>(this); }
  int sendlen() const { return static_cast<int>(offsetof(AuthRequest, auth_methods) + auth_method_count); }
};

}  // client

namespace server {

struct AuthResponse
{
  VersionField      version;
  AuthMethodField   auth_method;

  AuthResponse();

  operator char*() { return reinterpret_cast<char *>(this); }
  int recvlen() const { return static_cast<int>(sizeof(*this)); }

  bool validate() const;
};

}  // server

namespace client {

struct Request
{
  VersionField      version;
  CommandField      command;
  uint8_t           reserved;
  AddressTypeField  address_type;
  union
  {
    Ipv4Address     ipv4;
    Ipv6Address     ipv6;
    DomainName      domain;
  } dest_addr;

  Request(const Command cmd, const Ipv4Address& ipv4);

  operator const char*() const { return reinterpret_cast<const char *>(this); }
  int sendlen() const;
};

}  // client

namespace server {

struct Response
{
  VersionField      version;
  ReplyTypeField    reply_type;
  uint8_t           reserved;
  AddressTypeField  address_type;
  union
  {
    Ipv4Address     ipv4;
    Ipv6Address     ipv6;
    DomainName      domain;
  } bind_addr;

  Response();

  operator char*() { return reinterpret_cast<char *>(this); }
  int recvlen() const { return static_cast<int>(offsetof(Response, bind_addr)); }

  bool validate() const;
};

}  // server

#pragma pack(pop)

}  // socks5
}  // proxy


namespace proxy {
namespace socks5 {

template<typename T>
int ClientTcp::Send(const T& data)
{
  return Send(&data, sizeof(data));
}

template<typename T>
int ClientTcp::Recv(T& data)
{
  return Recv(&data, sizeof(data));
}

}  // socks5
}  // proxy

