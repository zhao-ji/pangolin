#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket
import SocketServer

import logbook

import icmp
from ThreadedICMPServer import ThreadedICMPServer

# global socket dict: identifier and tcp-stream-socket
demultiplexer = {}
# global shards: identifier and piece list
shards = {}

class ICMPRequestHandler(SocketServer.BaseRequestHandler):
    '''
    ICMP
    '''
    def handle(self):
        global demultiplexer
        global shards

        raw_data, local = self.request
        identifier, sequence, content = icmp.unpack_reply(raw_data)
        logbook.info("identifier: {} sequence: {}"
                     .format(identifier, sequence))

        if sequence == 6666:
            remote_addr = eval(content)
            remote = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(remote_addr)
            remote.settimeout(0.5)
            logbook.info(
                "connect the remote server: {}".format(remote_addr))

            demultiplexer[identifier] = remote

            icmp_body = 'ok'
        elif sequence == 8888:
            if identifier not in demultiplexer:
                packet = icmp.pack_reply(
                    identifier, sequence, content)
                local.sendto(packet, self.client_address)

            remote = demultiplexer[identifier]

            if len(content) == 0:
                remote.close()
                demultiplexer.pop(identifier, 0)

            logbook.info("send to remote:\n{}".format(content))
            remote.send(content)

            remote_recv = ''
            while True:
                try:
                    buf = remote.recv(8192)
                except:
                    logbook.info("empty buf")
                    break
                else:
                    logbook.info("buf:\n{}".format(buf))
                    remote_recv += buf
            if len(remote_recv) <= 4096:
                icmp_body = remote_recv
                logbook.info(
                    "the length of icmp_body is {}"
                    .format(len(icmp_body)))
                logbook.info("return direct")
            else:
                shards[identifier] = remote_recv
                icmp_body = "shards"
                logbook.info("shards")
        elif sequence == 9999:
                if not shards.get(identifier, '') \
                        or not len(shards.get(identifier, '')):
                    icmp_body = "over"
                    logbook.info("over")
                else:
                    icmp_body = shards[identifier][:4096]
                    shards[identifier] = shards[identifier][4096:]
        else:
            icmp_body = shards[identifier][sequence]
            logbook.info("shard content:\n{}".format(repr(icmp_body)))
            if sequence == len(shards[identifier]) - 1:
                shards.pop(identifier, 0)

        logbook.info("send back the content")
        packet = icmp.pack_reply(identifier, sequence, icmp_body)
        local.sendto(packet, self.client_address)


if __name__ == '__main__':
    local_log = logbook.StderrHandler()
    local_log.format_string = (
        u'[{record.time:%H:%M:%S}] '
        u'lineno:{record.lineno} '
        u'{record.level_name}:{record.message}')
    local_log.push_application()

    server = ThreadedICMPServer(('0.0.0.0', 1), ICMPRequestHandler)
    logbook.info("start ICMP server")
    server.serve_forever()
