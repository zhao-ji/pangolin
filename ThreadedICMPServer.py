#!/usr/bin/env python
# -*- coding: utf8 -*-

import select
import socket
import SocketServer

SERVER_ADDR = ("23.226.226.196", 1)

class ICMPServer(SocketServer.BaseServer):
    """Base class for various socket-based server classes.

    Defaults to synchronous IP stream (i.e., TCP).

    """

    address_family = socket.AF_INET

    socket_type = socket.SOCK_RAW

    protocol = socket.IPPROTO_ICMP

    request_queue_size = 5

    allow_reuse_address = True

    max_packet_size = 8192

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=False):
        """Constructor.  May be extended, do not override."""
        SocketServer.BaseServer.__init__(
            self, server_address, RequestHandlerClass)
        self.socket = socket.socket(
            self.address_family, self.socket_type,
            self.protocol)
        if bind_and_activate:
            self.server_bind()

    def server_bind(self):
        """Called by constructor to bind the socket.

        May be overridden.

        """
        if self.allow_reuse_address:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_address = SERVER_ADDR

    def fileno(self):
        """Return socket file number.

        Interface required by select().

        """
        return self.socket.fileno()

    def get_request(self):
        """Get the request and client address from the socket.

        May be overridden.

        """
        data, client_addr = self.socket.recvfrom(self.max_packet_size)
        return (data, self.socket), client_addr


class ThreadedICMPServer(SocketServer.ThreadingMixIn, ICMPServer):
    pass
