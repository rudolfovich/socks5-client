#include "socks5.h"
#include <iostream>

using namespace std;

int main(int argc, char *argv[])
{
  using proxy::socks5::Ipv4;
  using proxy::socks5::Ipv4Address;
  using proxy::socks5::ClientTcp;
  using proxy::socks5::ErrorGeneric;

  try
  {
    ClientTcp conn(Ipv4(192,168,1,101,1080));
    Ipv4Address binded = {};
    conn.Connect(Ipv4(192,168,0,176,8899), binded);
    conn.Send("\n\n === Hello, Valdemar! === \n\n");
    conn.Disconnect();
  }
  catch (const ErrorGeneric &ex)
  {
    string s(ex.what());
    cout << "Error: " << s << endl;
    return 1;
  }
  return 0;
}
