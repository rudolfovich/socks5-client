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

typedef std::string      string;
typedef const string     cstring;

class fmt
{
  std::ostringstream stream_;
public:
  template<typename T> fmt(const T& s) : stream_() { stream_ << s; }
  template<typename T> fmt& operator << (const T& val) { stream_ << val; return *this; }
  fmt& operator << (const Ipv4Address& val);
  string str() const { return stream_.str(); }
  operator string() const { return stream_.str(); }
};

class ErrorGeneric                  : public std::runtime_error    { public: ErrorGeneric(cstring& msg) : std::runtime_error(msg) {} };
class ErrorNetworkFailure           : public ErrorGeneric          { public: ErrorNetworkFailure(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorSocksFailure             : public ErrorGeneric          { public: ErrorSocksFailure(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorNotAllowed               : public ErrorGeneric          { public: ErrorNotAllowed(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorNetUnreachable           : public ErrorGeneric          { public: ErrorNetUnreachable(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorHostUnreachable          : public ErrorGeneric          { public: ErrorHostUnreachable(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorConnRefused              : public ErrorGeneric          { public: ErrorConnRefused(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorTtlExpired               : public ErrorGeneric          { public: ErrorTtlExpired(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorUnsupportedCommand       : public ErrorGeneric          { public: ErrorUnsupportedCommand(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorUnsupportedAddrType      : public ErrorGeneric          { public: ErrorUnsupportedAddrType(cstring& msg) : ErrorGeneric(msg) {}  };
class ErrorNoAcceptableMethodsFound : public ErrorGeneric          { public: ErrorNoAcceptableMethodsFound(cstring& msg) : ErrorGeneric(msg) {}  };

}  // socks5
}  // proxy


#pragma pack(push, 1)

namespace proxy {

namespace socks5 {

//
// https://tools.ietf.org/html/rfc1928
//

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


static inline Ipv4Address Ipv4(uint32_t _addr, uint16_t _port)
{
  Ipv4Address a = {};
  a.addr = _addr;
  a.port = _port;
  return a;
}

static inline Ipv4Address Ipv4(uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4, uint16_t _port)
{
  Ipv4Address a = {};
  a.part1 = p1;
  a.part2 = p2;
  a.part3 = p3;
  a.part4 = p4;
  a.port  = _port;
  return a;
}


inline fmt& fmt::operator <<(const Ipv4Address& val)
{
  stream_ << static_cast<int>(val.part1) << "."
          << static_cast<int>(val.part2) << "."
          << static_cast<int>(val.part3) << "."
          << static_cast<int>(val.part4) << ":"
          << static_cast<int>(val.port);
  return *this;
}

struct Ipv6Address
{
  union
  {
    uint16_t    parts[8];
    struct
    {
      uint16_t  part1;
      uint16_t  part2;
      uint16_t  part3;
      uint16_t  part4;
      uint16_t  part5;
      uint16_t  part6;
      uint16_t  part7;
      uint16_t  part8;
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

typedef Version       VersionField;
typedef AuthMethod    AuthMethodField;
typedef Command       CommandField;
typedef AddressType   AddressTypeField;
typedef ReplyType     ReplyTypeField;

namespace client {

// The client connects to the server, and sends a version
// identifier/method selection message:
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
//

struct AuthRequest
{
  VersionField      version;
  uint8_t           auth_method_count;
  AuthMethodField   auth_methods[255];

  AuthRequest(AuthMethod method)
    : version(kSocksVersion)
    , auth_method_count(1)
  {
    memset(auth_methods, 0, sizeof(auth_methods));
    auth_methods[0] = static_cast<AuthMethodField>(method);
  }

  operator const char*() const { return reinterpret_cast<const char *>(this); }
  int sendlen() const { return static_cast<int>(offsetof(AuthRequest, auth_methods) + auth_method_count); }
};

}  // client

namespace server {

// The server selects from one of the methods given in METHODS, and
// sends a METHOD selection message:
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+

struct AuthResponse
{
  VersionField      version;
  AuthMethodField   auth_method;

  AuthResponse()
    : version(Version_Undefined)
    , auth_method(AuthMethod_Undefined)
  {}

  operator char*() { return reinterpret_cast<char *>(this); }
  int recvlen() const { return static_cast<int>(sizeof(*this)); }

  bool validate() const {
    if (version == Version_Undefined) return false;
    if (version != kSocksVersion) throw ErrorGeneric(fmt("Unsupported version: ") << version);
    if (auth_method == AuthMethod_Undefined)  return false;
    if (auth_method == AuthMethod_NoAcceptableMethods) throw ErrorNoAcceptableMethodsFound("No acceptable methods was found.");
    return true;
  }
};

}  // server


// Once the method-dependent subnegotiation has completed, the client
// sends the request details.  If the negotiated method includes
// encapsulation for purposes of integrity checking and/or
// confidentiality, these requests MUST be encapsulated in the method-
// dependent encapsulation.
//
// The SOCKS request is formed as follows:
//
//      +----+-----+-------+------+----------+----------+
//      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//      +----+-----+-------+------+----------+----------+
//      | 1  |  1  | X'00' |  1   | Variable |    2     |
//      +----+-----+-------+------+----------+----------+
//
//   Where:
//
//    o  VER    protocol version: X'05'
//    o  CMD
//       o  CONNECT X'01'
//       o  BIND X'02'
//       o  UDP ASSOCIATE X'03'
//    o  RSV    RESERVED
//    o  ATYP   address type of following address
//       o  IP V4 address: X'01'
//       o  DOMAINNAME: X'03'
//       o  IP V6 address: X'04'
//    o  DST.ADDR       desired destination address
//    o  DST.PORT desired destination port in network octet
//       order
//
//  Addressing
//
//  In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
//  the type of address contained within the field:
//
//         o  X'01'
//  the address is a version-4 IP address, with a length of 4 octets
//
//         o  X'03'
//  the address field contains a fully-qualified domain name.  The first
//  octet of the address field contains the number of octets of name that
//  follow, there is no terminating NUL octet.
//
//         o  X'04'
//  the address is a version-6 IP address, with a length of 16 octets.
//
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

  Request(const Command cmd, const Ipv4Address& ipv4)
    : version(kSocksVersion)
    , command(static_cast<CommandField>(cmd))
    , reserved(0)
    , address_type(AddressType_Ipv4)
    , dest_addr()
  {
    dest_addr.ipv4.addr = htonl (ipv4.addr);
    dest_addr.ipv4.port = htons (ipv4.port);
  }

  operator const char*() const { return reinterpret_cast<const char *>(this); }
  int sendlen() const
  {
    size_t len = offsetof(Request, dest_addr);
    switch (address_type) {
      case AddressType_Ipv4:        return static_cast<int>(len + sizeof(dest_addr.ipv4));
      case AddressType_Ipv6:        return static_cast<int>(len + sizeof(dest_addr.ipv6));
      case AddressType_DomainName:  return static_cast<int>(len + sizeof(dest_addr.domain.length) + dest_addr.domain.length);
      default: throw ErrorGeneric(fmt("Unsupported address type: ") << address_type);
    }
  }
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

  Response()
    : version(Version_Undefined)
    , reply_type(ReplyType_Undefined)
    , reserved(0x00)
    , address_type(AddressType_Undefined)
    , bind_addr()
  {}
  operator char*() {
    return reinterpret_cast<char *>(this);
  }
  int recvlen() const {
    return static_cast<int>(offsetof(Response, bind_addr));
  }
  bool validate() const {
    if (version == Version_Undefined) return false;
    if (version != kSocksVersion) throw ErrorGeneric(fmt("Unsupported version: ") << version);
    if (reply_type == ReplyType_Undefined)  return false;
    if (reply_type != ReplyType_Succeeded) {
      #define case_reply_type(err) \
          case ReplyType_ ## err: throw Error ## err("ReplyType is " # err);
      switch (reply_type) {
        case_reply_type(SocksFailure        );
        case_reply_type(NotAllowed          );
        case_reply_type(NetUnreachable      );
        case_reply_type(HostUnreachable     );
        case_reply_type(ConnRefused         );
        case_reply_type(TtlExpired          );
        case_reply_type(UnsupportedCommand  );
        case_reply_type(UnsupportedAddrType );
        default: throw ErrorGeneric(fmt("Unsuported reply type ") << reply_type);
      }
      #undef case_reply_type
    }
    if (address_type == AddressType_Undefined) return false;
    if (address_type != AddressType_Ipv4 &&
        address_type != AddressType_Ipv6 &&
        address_type != AddressType_DomainName) throw ErrorGeneric(fmt("Unsuported address type ") << address_type);
    return true;
  }

};

}  // server

}  // socks5


/*
The SOCKS5 protocol is defined in RFC 1928. It is an extension of the SOCKS4 protocol;
it offers more choices for authentication and adds support for IPv6 and UDP, the latter
of which can be used for DNS lookups. The initial handshake consists of the following:

Client connects and sends a greeting, which includes a list of authentication methods supported.
Server chooses one of the methods (or sends a failure response if none of them are acceptable).
Several messages may now pass between the client and the server, depending on the authentication method chosen.
Client sends a connection request similar to SOCKS4.
Server responds similar to SOCKS4.
The authentication methods supported are numbered as follows:

0x00: No authentication
0x01: GSSAPI[9]
0x02: Username/password[10]
0x03–0x7F: methods assigned by IANA[11]
0x80–0xFE: methods reserved for private use
The initial greeting from the client is

field 1: SOCKS version number (must be 0x05 for this version)
field 2: number of authentication methods supported, 1 byte
field 3: authentication methods, variable length, 1 byte per method supported

The server's choice is communicated:
field 1: SOCKS version, 1 byte (0x05 for this version)
field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
The subsequent authentication is method-dependent. Username and password authentication (method 0x02) is described in RFC 1929:

For username/password authentication the client's authentication request is
field 1: version number, 1 byte (must be 0x01)
field 2: username length, 1 byte
field 3: username
field 4: password length, 1 byte
field 5: password

Server response for username/password authentication:
field 1: version, 1 byte
field 2: status code, 1 byte
0x00 = success
any other value = failure, connection must be closed
The client's connection request is

field 1: SOCKS version number, 1 byte (must be 0x05 for this version)
field 2: command code, 1 byte:
0x01 = establish a TCP/IP stream connection
0x02 = establish a TCP/IP port binding
0x03 = associate a UDP port
field 3: reserved, must be 0x00
field 4: address type, 1 byte:
0x01 = IPv4 address
0x03 = Domain name
0x04 = IPv6 address
field 5: destination address of
4 bytes for IPv4 address
1 byte of name length followed by the name for domain name
16 bytes for IPv6 address
field 6: port number in a network byte order, 2 bytes
Server response:

field 1: SOCKS protocol version, 1 byte (0x05 for this version)
field 2: status, 1 byte:
0x00 = request granted
0x01 = general failure
0x02 = connection not allowed by ruleset
0x03 = network unreachable
0x04 = host unreachable
0x05 = connection refused by destination host
0x06 = TTL expired
0x07 = command not supported / protocol error
0x08 = address type not supported
field 3: reserved, must be 0x00
field 4: address type, 1 byte:
0x01 = IPv4 address
0x03 = Domain name
0x04 = IPv6 address
field 5: destination address of
4 bytes for IPv4 address
1 byte of name length followed by the name for domain name
16 bytes for IPv6 address
field 6: network byte order port number, 2 bytes
*/

}  // proxy

#pragma pack(pop)

namespace proxy {

namespace socks5 {

class ClientTcp
{
  const Ipv4Address proxy_addr_;
  SOCKET socket_;

public:
  ClientTcp(const Ipv4Address& proxy_addr);
  ~ClientTcp();
  void Connect(const Ipv4Address& host, Ipv4Address& binded_addr);
  void Disconnect();
  int Recv(void *data, size_t size);
  int Send(const void *data, size_t size);

  int Recv(string& data);
  int Send(const string& data);

  template<typename T> int Recv(T& data);
  template<typename T> int Send(const T& data);
};

inline int ClientTcp::Recv(string& data)
{
  return Recv(&data[0], data.length());
}

inline int ClientTcp::Send(const string& data)
{
  return Send(&data[0], data.length());
}

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
