# SPDX-License-Identifier: Apache-2.0
from socket import socket
from testing import assert_equal


def test_gethostname():
    assert_equal(socket.gethostname(), "")


def test_inet_pton():
    var packed_ip = socket.inet_pton(AF_INET, "127.0.0.1")


def test_inet_ntop():
    var in_addr = socket._in_addr()
    in_addr.s_addr = socket.inet_pton(AF_INET, "127.0.0.1")
    assert_equal(socket.inet_ntop(AF_INET, in_addr), "127.0.0.1")


def test_socket():
    # Create IPv4 TCP socket
    var tcp_socket = socket.create_socket(AF_INET, SOCK_STREAM, 0)
    tcp_socket.connect("127.0.0.1", 22)

    print("socket fileno = ", tcp_socket.fileno())

    var peer = tcp_socket.getpeername()

    print("getpeername = ", peer[0])
    print("getpeername = ", peer[1])

    var ptr = DTypePointer[DType.uint8].alloc(12)
    var bytes_read = tcp_socket.read(ptr, 12)
    print("bytes read", bytes_read)

    var bytes = tcp_socket.read_bytes(12)
    var ascii_str = String(bytes, 12)
    print("ascii_str = ", ascii_str)

    tcp_socket.close()

    # Create IPv4 UDP socket
    var udp_socket = socket.create_socket(AF_INET, SOCK_DGRAM, 0)
    udp_socket.close()

    # Create IPv6 TCP socket
    var tcpv6_socket = socket.create_socket(AF_INET6, SOCK_STREAM, 0)
    tcpv6_socket.close()

    # Create IPv6 UDP socket
    var udpv6_socket = socket.create_socket(AF_INET6, SOCK_DGRAM, 0)
    udpv6_socket.close()


def main():
    test_gethostname()
    test_inet_pton()
    test_inet_ntop()
