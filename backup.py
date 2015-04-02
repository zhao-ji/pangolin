#! /usr/bin/env python
# -*- coding: utf8 -*-

import socket

import logbook

import icmp

if __name__ == "__main__":
    local_log = logbook.StderrHandler()
    local_log.format_string = (u'[{record.time:%H:%M:%S}] '
                               u'lineno:{record.lineno} '
                               u'{record.level_name}:{record.message}')
    local_log.push_application()

    # global socket dict: identifier and tcp-stream-socket
    demultiplexer = {}

    # the public network interface
    HOST = socket.gethostbyname(socket.gethostname())
    # create a raw socket and bind it to the public interface
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((HOST, 0))
    logbook.info("the server start working")

    while True:
        raw_data, addr = sock.recvfrom(4096)
        logbook.info("the send address is {}".format(addr))
        identifier, sequence, content = icmp.unpack_reply(raw_data)
        logbook.info(
            "identifier: {}, sequence: {}, keys: {}"
            .format(identifier, sequence, demultiplexer.keys()))

        if sequence == 6666:
            # start connect the web app server
            remote_addr = eval(content)
            remote = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(remote_addr)
            logbook.info(
                "connect the remote server: {}".format(remote_addr))

            demultiplexer[identifier] = remote

            packet = icmp.pack_reply(
                identifier, sequence, "ok")
            sock.sendto(packet, addr)
        elif sequence == 8888:
            if identifier not in demultiplexer:
                logbook.info(
                    "not exist identifier: {}".format(identifier))
                packet = icmp.pack_reply(
                    identifier, sequence, content)
                sock.sendto(packet, addr)
                continue

            # start exchange the data between the two side
            remote = demultiplexer[identifier]

            if len(content) <= 0:
                logbook.info(
                    "empty content, identifier: {}"
                    .format(identifier))
                remote.close()
                demultiplexer.pop(identifier, 0)
                continue

            logbook.info("the http body: {}".format(content))
            logbook.info("http body len: {}".format(len(content)))
            send_length = remote.send(content)
            logbook.info("send length :{}".format(send_length))
            remote_recv = ''
            while True:
                buf = remote.recv(1024)
                logbook.info("remote recv: \n\n{}".format(buf))
                if not len(buf):
                    break
                remote_recv += buf
            # remote_recv = remote.recv(4096)
            logbook.info(
                "remote recv len: {}".format(len(remote_recv)))
            packet = icmp.pack_reply(
                identifier, sequence, remote_recv)
            sock.sendto(packet, addr)
        else:
            logbook.info("some situation occur, content:\n{}"
                         .format(content))
            packet = icmp.pack_reply(identifier, sequence, content)
            sock.sendto(packet, addr)
