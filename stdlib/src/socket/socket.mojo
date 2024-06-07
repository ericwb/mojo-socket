# SPDX-License-Identifier: Apache-2.0
from sys import external_call
from sys import os_is_linux
from sys import os_is_windows
from memory import DTypePointer
from sys import sizeof


# Socket types
alias SOCK_STREAM = 1
alias SOCK_DGRAM = 2
alias SOCK_RAW = 3
alias SOCK_RDM = 4
alias SOCK_SEQPACKET = 5

# Protocols
alias AF_UNSPEC = 0
alias AF_UNIX = 1
alias AF_INET = 2
alias AF_INET6 = 10 if os_is_linux() else 23 if os_is_windows() else 30

# Socket domains
alias PF_INET = AF_INET
alias PF_INET6 = AF_INET6


# typedef __uint8_t       sa_family_t;
alias sa_family_t = UInt8

# typedef __uint32_t      in_addr_t;      /* base type for internet address */
alias in_addr_t = UInt32

# typedef __uint16_t      in_port_t;
alias in_port_t = UInt16


# struct sockaddr {
#     __uint8_t       sa_len;         /* total length */
#     sa_family_t     sa_family;      /* [XSI] address family */
#     char            sa_data[14];    /* [XSI] addr value */
# };
@value
@register_passable("trivial")
struct _c_sockaddr(Stringable):
    var sa_len: UInt8
    var sa_family: sa_family_t
    var sa_data: StaticTuple[UInt8, 14]

    fn __init__(inout self):
        self.sa_len = 0
        self.sa_family = 0
        self.sa_data = StaticTuple[UInt8, 14](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    fn __str__(self) -> String:
        var res = String("{\n")
        res += "sa_len: " + str(self.sa_len) + ",\n"
        res += "sa_family: " + str(self.sa_family) + ",\n"
        return res + "}"


# struct in_addr {
#     in_addr_t s_addr;
# };
@value
struct _in_addr:
    var s_addr: in_addr_t

    fn __init__(inout self):
        self.s_addr = 0


# struct sockaddr_in {
#     __uint8_t       sin_len;
#     sa_family_t     sin_family;
#     in_port_t       sin_port;
#     struct  in_addr sin_addr;
#     char            sin_zero[8];
# };
@value
struct _c_sockaddr_in(Stringable):
    var sin_len: UInt8
    var sin_family: sa_family_t
    var sin_port: in_port_t
    var sin_addr: _in_addr
    var sin_zero: StaticTuple[Int8, 8]

    fn __init__(inout self):
        self.sin_len = 1 + 1 + 2 + 4 + 8
        self.sin_family = 0
        self.sin_port = 0
        self.sin_addr = _in_addr()
        self.sin_addr.s_addr = 0
        self.sin_zero = StaticTuple[Int8, 8](0, 0, 0, 0, 0, 0, 0, 0)

    fn __str__(self) -> String:
        var res = String("{\n")
        res += "sin_len: " + str(self.sin_len) + ",\n"
        res += "sin_family: " + str(self.sin_family) + ",\n"
        res += "sin_port: " + str(self.sin_port) + ",\n"
        res += "sin_addr: " + str(self.sin_addr.s_addr) + ",\n"
        return res + "}"

@value
struct Socket:
    """An initialized socket."""

    var sock_fd: UInt32 #Optional[Int32]

    fn __init__(inout self):
        """Default constructor."""
        self.sock_fd = 0

    fn __init__(inout self, family: UInt8, type: Int32, protocol: Int32) raises:
        """Construct the socket.

        Args:
            family: The socket family.
            type: The socket type.
            protocol: The socket protocol.
        """
        var fd = external_call["socket", Int32](family, type, protocol)

        if fd == -1:
            raise "Unable to initialize socket"

        self.sock_fd = fd.cast[DType.uint32]()

    fn connect(inout self, hostname: String, port: UInt16) raises:
        var sockaddr_in = _c_sockaddr_in()
        sockaddr_in.sin_family = AF_INET
        sockaddr_in.sin_port = htons(port)
        sockaddr_in.sin_len = sizeof[_c_sockaddr_in]()
        sockaddr_in.sin_addr.s_addr = inet_pton(AF_INET, hostname)

        # int connect(int, const struct sockaddr *, socklen_t) __DARWIN_ALIAS_C(connect);
        # int connect(int socket, const struct sockaddr *address, socklen_t address_len)
        var err = external_call["connect", Int32](
            self.sock_fd,
            UnsafePointer.address_of(sockaddr_in),
            sockaddr_in.sin_len
        )

        if err == -1:
            var error_str = String("connect")
            _ = external_call["perror", Pointer[NoneType]](error_str._as_ptr())
            raise error_str

    #fn read(inout self):

    #fn write(inout self):

    fn close(inout self) raises:
        """Closes the socket."""
        if not self.sock_fd:
            return

        var err = external_call["close", Int32](self.sock_fd)
        if err == -1:
            raise "Unable to close socket"

        self.sock_fd = 0


fn create_socket(family: UInt8 = AF_INET, type: Int32 = SOCK_STREAM, protocol: Int32 = 0) raises -> Socket:
    """Creates a new socket, returning a SocketHandle.

    Args:
      family: The socket family.
      type: The socket type.
      protocol: The socket protocol.

    Returns:
      A Socket.
    """
    return Socket(family, type, protocol)


fn htons(port: UInt16) -> UInt16:
    return external_call["htons", UInt16](port)


fn inet_pton(family: UInt8, ip_addr: String) raises -> UInt32:
    var num: UInt32 = 0

    var err = external_call["inet_pton", Int32](
        family,
        ip_addr._as_ptr(),
        UnsafePointer.address_of(num),
    )

    if err < 1:
        var error_str = String("inet_pton")
        _ = external_call["perror", Pointer[NoneType]](error_str._as_ptr())
        raise error_str

    return num


fn main() raises:
    # Create IPv4 TCP socket
    var tcp_socket = create_socket(AF_INET, SOCK_STREAM, 0)
    tcp_socket.connect("127.0.0.1", 22)

    # Create IPv4 UDP socket
    var udp_socket = create_socket(AF_INET, SOCK_DGRAM, 0)

    # Create IPv6 TCP socket
    var tcpv6_socket = create_socket(AF_INET6, SOCK_STREAM, 0)

    # Create IPv6 UDP socket
    var udpv6_socket = create_socket(AF_INET6, SOCK_DGRAM, 0)

    tcp_socket.close()
    udp_socket.close()
    tcpv6_socket.close()
    udpv6_socket.close()
