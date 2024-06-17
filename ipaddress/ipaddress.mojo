# SPDX-License-Identifier: Apache-2.0
import socket


trait IPAddress:
    fn is_multicast(self) -> Bool:
        ...

    fn is_private(self) -> Bool:
        ...

    fn is_loopback(self) -> Bool:
        ...

    fn is_link_local(self) -> Bool:
        ...

    fn is_reserved(self) -> Bool:
        ...

    fn is_global(self) -> Bool:
        ...

    fn is_unspecified(self) -> Bool:
        ...


struct IPv4Address(IPAddress):
    var version: Int
    var max_prefixlen: Int
    var _ip: UInt32

    fn __init__(inout self):
        self.version = 0
        self.max_prefixlen = 0
        self._ip = 0

    fn __init__(inout self, address: String) raises:
        self.version = 4
        self.max_prefixlen = 32
        try:
            self._ip = socket.inet_pton(socket.AF_INET, address)
        except:
            raise Error("AddressValueError: invalid IPv4 address string")
        self._ip = _ntohl(self._ip)

    fn is_multicast(self) -> Bool:
        # Check self._ip 224.0.0.0/4
        return (self._ip & 0xF0000000) == 0xE0000000

    fn is_private(self) -> Bool:
        # Check for 10.0.0.0/8
        if (self._ip & 0xFF000000) == 0x0A000000:
            return True

        # Check for 172.16.0.0/12
        if (self._ip & 0xFFF00000) == 0xAC100000:
            return True

        # Check for 192.168.0.0/16
        if (self._ip & 0xFFFF0000) == 0xC0A80000:
            return True

        return False

    fn is_loopback(self) -> Bool:
        # Check for 127.0.0.0/8
        return (self._ip & 0xFF000000) == 0x7F000000

    fn is_link_local(self) -> Bool:
        return (self._ip & 0xFFFF0000) == 0xA9FE0000

    fn is_reserved(self) -> Bool:
        return (self._ip & 0xFF000000) == 0x00000000 or (self._ip & 0xF0000000) == 0xF0000000

    fn is_global(self) -> Bool:
        if self.is_private() or self.is_loopback() or self.is_multicast() or self.is_link_local() or self.is_reserved():
            return False

        return True

    fn is_unspecified(self) -> Bool:
        return self._ip == 0x00000000


# uint32_t ntohl(uint32_t netlong);
fn _ntohl(addr: UInt32) -> UInt32:
    return external_call["ntohl", UInt32](addr)


struct IPv6Address:
    var version: Int
    var max_prefixlen: Int
    var _ip: UInt32

    fn __init__(inout self):
        self.version = 0
        self.max_prefixlen = 0
        self._ip = 0

    fn __init__(inout self, address: String) raises:
        self.version = 6
        self.max_prefixlen = 128
        try:
            self._ip = socket.inet_pton(socket.AF_INET6, address)
        except:
            raise Error("AddressValueError: invalid IPv6 address string")

#struct IPv4Network:

#struct IPv6Network:


#struct IPv4Interface:

#struct IPv6Interface:

#fn abort[result: AnyType = NoneType]() -> result:


fn ip_address(address: String) raises -> IPv4Address:
    try:
        return IPv4Address(address)
    except:
        pass

    #try:
    #    return IPv6Address(address)
    #except:
    #    pass

    raise Error("ValueError: not a valid IPv4 or IPv6 address")

#fn ip_network(address, strict=True) raises -> IPv4Network:


#fn ip_interface(address) raises -> IPv4Interface:


fn main() raises:

    var ipv4address = ip_address("127.0.0.1")

    #var ipv6address = IPv6Address("127.0.0.1")
