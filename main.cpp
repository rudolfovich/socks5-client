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
    const auto proxy(Ipv4(192,168,1,101,1080));
    const auto target(Ipv4(192,168,0,176,8899));
    Ipv4Address binded = {};
    ClientTcp socks5;

    socks5.Connect(proxy, target, binded);
    socks5.Send("\n\n === Hello, Valdemar! === \n\n");
    socks5.Disconnect();
  }
  catch (const ErrorGeneric &ex)
  {
    cout << "Error: " << ex.what() << endl;
    return 1;
  }
  return 0;
}
