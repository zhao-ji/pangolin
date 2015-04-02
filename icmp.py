#! /usr/bin/env python
# -*- coding: utf8 -*-

import struct

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_CODE = 0
ICMP_INIT_CHECKSUM = 0

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    # filed with zero if the length of msg is odd
    if len(msg)%2 is 1:
        msg += b'\x00'
    # process the internet checksum
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    # strange operate
    answer = ~s & 0xffff
    return answer >> 8 | (answer << 8 & 0xff00)

def pack(identifier, sequence, content):
    header = struct.pack(
        ">bbHHH",
        ICMP_ECHO_REQUEST, ICMP_ECHO_CODE,
        ICMP_INIT_CHECKSUM, identifier, sequence)

    header_checksum = checksum(header + content)

    header = struct.pack(
        ">bbHHH",
        ICMP_ECHO_REQUEST, ICMP_ECHO_CODE,
        header_checksum, identifier, sequence)

    return header + content

def pack_reply(identifier, sequence, content):
    header = struct.pack(
        ">bbHHH",
        ICMP_ECHO_REPLY, ICMP_ECHO_CODE,
        ICMP_INIT_CHECKSUM, identifier, sequence)

    header_checksum = checksum(header + content)

    header = struct.pack(
        ">bbHHH",
        ICMP_ECHO_REPLY, ICMP_ECHO_CODE,
        header_checksum, identifier, sequence)

    return header + content

def unpack(data):
    return data[28:]

def unpack_reply(data):
    identifier, sequence = struct.unpack(">HH", data[24:28])
    content = data[28:]
    return identifier, sequence, content
