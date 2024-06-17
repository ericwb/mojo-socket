from ipaddress import ipaddress
from socket import inet_pton


fn main() raises:
    #var ipv4address = ipaddress.IPv4Address("127.0.0.1")
    var ipv4address = ipaddress.ip_address("127.0.0.1")
    print(ipv4address.is_loopback())

    ipv4address = ipaddress.ip_address("192.168.4.111")
    print(ipv4address.is_private())

    ipv4address = ipaddress.ip_address("10.10.1.23")
    print(ipv4address.is_private())

    ipv4address = ipaddress.ip_address("172.16.1.50")
    print(ipv4address.is_private())

    ipv4address = ipaddress.ip_address("224.0.0.1")
    print(ipv4address.is_multicast())

    var packed_ip = inet_pton(socket.AF_INET, "127.0.0.1")
