# Concord
#
# Copyright (c) 2019 VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache 2.0 license (the "License").
# You may not use this product except in compliance with the Apache 2.0 License.
#
# This product may include a number of subcomponents with separate copyright
# notices and license terms. Your use of these subcomponents is subject to the
# terms and conditions of the subcomponent's license, as noted in the LICENSE
# file.

# This code requires python 3.5 or later
import struct
import ssl
import socket
import trio
import time
import os

import bft_msgs
from bft_config import Config, Replica

# All test communication expects ports to start from 3710
BASE_PORT = 3710

class ReqSeqNum:
    def __init__(self):
        self.time_since_epoch_milli = int(time.time()*1000)
        self.count = 0
        self.max_count = 0x3FFFFF
        self.max_count_len = 22

    def next(self):
        """
        Calculate the next req_seq_num.
        Return the calculated value as an int sized for 64 bits
        """
        milli = int(time.time()*1000)
        if milli > self.time_since_epoch_milli:
            self.time_since_epoch_milli = milli
            self.count = 0
        else:
            if self.count == self.max_count:
                self.time_since_epoch_milli += 1
                self.count = 0
            else:
                self.count += 1
        return self.val()

    def val(self):
        """ Return an int sized for 64 bits """
        assert(self.count <= self.max_count)
        r = self.time_since_epoch_milli << self.max_count_len
        r = r | self.count
        return r

# class TlsConnection: 

class TlsClient:
    def __enter__(self):
        """context manager method for 'with' statements"""
        return self

    def __exit__(self, *args):
        """context manager method for 'with' statements"""
        for s in self.ssock.values():
            s.close()

    def __init__(self, config, replicas):
        print (f'Yehuda {os.getcwd()} {config} {replicas}')
        self.config = config
        self.replicas = replicas
        self.req_seq_num = ReqSeqNum()
        self.client_id = config.id
        self.replies = dict()
        self.primary = None
        self.reply = None
        self.retries = 0
        self.msgs_sent = 0
        self.reply_quorum = 2*config.f + config.c + 1
        self.sock_bound = False
        self.ssock = dict()
        client_cert = 'certs/4/client/client.cert'
        client_key = 'certs/4/client/pk.pem'
        for replica in self.replicas: 
            sock = socket.socket(trio.socket.AF_INET,
                            trio.socket.SOCK_STREAM)

            server_cert = f'certs/{replica.id}/server/server.cert'
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
            context.load_cert_chain(client_cert,client_key)
            context.load_verify_locations(server_cert)
            context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
            self.ssock[replica.id] = context.wrap_socket(sock)
            # ssl.create_default_context(purpose=Purpose.SERVER_AUTH, cafile=None, capath=None, cadata=None)
            # context.    
            # context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
            # context.load_cert_chain(certfile=client_cert, keyfile=client_key)
            # context.check_hostname = False
            # self.ssock[replica.id] = context.wrap_socket(
            #     sock, 
            #     client_key, 
            #     client_cert, 
            #     False, 
            #     ssl.CERT_REQUIRED, 
            #     ssl.PROTOCOL_TLS,
            #     # ssl_version={see docs}, 
            #     server_cert, 
            #     True, 
            #     True, 
            #     "ECDHE-ECDSA-AES256-GCM-SHA384")


        # # self.connections=
        # print (f'Yehuda primary {self.primary}')

        # self.host_addr = self.primary.ip
        # self.host_port = self.primary.port
        # server_cert = 'certs/0/server/server.cert'
        # client_cert = 'certs/4/client/client.cert'
        # client_key = 'certs/4/client/pk.pem'


        # await trio.sleep(100)
        # ssock.connect((host_addr, host_port))
        # print("SSL established. Peer: {}".format(ssock.getpeercert()))
        # print("Sending: 'Hello, world!")
        # ssock.send(b"Hello, world!")
        # print("Closing connection")
        # ssock.close()

        # self.sock = trio.SSLStream(self.xsock,context)

    async def write(self, msg, seq_num=None, cid=None, pre_process=False):
        """ A wrapper around sendSync for requests that mutate state """
        return await self.sendSync(msg, False, seq_num, cid, pre_process)

    async def read(self, msg, seq_num=None, cid=None):
        """ A wrapper around sendSync for requests that do not mutate state """
        return await self.sendSync(msg, True, seq_num, cid)

    async def sendSync(self, msg, read_only, seq_num=None, cid=None, pre_process=False):
        """
        Send a client request and wait for a quorum (2F+C+1) of replies.

        Return a single reply message if a quorum of replies matches.
        Otherwise, raise a trio.TooSlowError indicating the request timed out.

        Retry Strategy:
            If the request is a write and the primary is known then send only to
            the primary on the first attempt. Otherwise, if the request is read
            only or the primary is unknown, then send to all replicas on the
            first attempt.

            After `config.retry_timeout_milli` without receiving a quorum of
            identical replies, then clear the replies and send to all replicas.
            Continue this strategy every `retry_timeout_milli` until
            `config.req_timeout_milli` elapses. If `config.req_timeout_milli`
            elapses then a trio.TooSlowError is raised.

         Note that this method also binds the socket to an appropriate port if
         not already bound.
        """
        if not self.sock_bound:
            await self.bind()

        print(f'Yehuda sendsync {msg} ')

        if seq_num is None:
            seq_num = self.req_seq_num.next()

        if cid is None:
            cid = str(seq_num)
        data = bft_msgs.pack_request(
                    self.client_id, seq_num, read_only, self.config.req_timeout_milli, cid, msg, pre_process)

        print(f'Yehuda sendsync packed {data} ')

        # Raise a trio.TooSlowError exception if a quorum of replies
        # with trio.fail_after(self.config.req_timeout_milli/1000):
        with trio.fail_after(5):
            self.reset_on_new_request()
            self.retries = 0
            return await self.send_loop(data, read_only)

    def reset_on_retry(self):
        """Reset any state that must be reset during retries"""
        self.replies = dict()
        self.primary = None
        self.retries += 1

    def reset_on_new_request(self):
        """Reset any state that must be reset during new requests"""
        self.replies = dict()
        self.reply = None
        self.retries = 0

    async def bind(self):
        # Each port is a function of its client_id
        # self.ssock.connect((self.host_addr, self.host_port))
        await trio.sleep(10)
        for rid, sock in self.ssock.items():
            replica = self.replicas[rid]
            sock.connect((replica.ip,replica.port))
            print("*** Yehuda SSL established. Peer: {}".format(sock.getpeercert()))

        # port = BASE_PORT + 2*self.client_id
        # await self.sock.bind(("127.0.0.1", port))
        self.sock_bound = True


    async def send_loop(self, data, read_only):
        """
        Send and wait for a quorum of replies. Keep retrying if a quorum
        isn't received. Eventually the max request timeout from the
        outer scope will fire cancelling all sub-scopes and their coroutines
        including this one.
        """
        while self.reply is None:
            with trio.move_on_after(5):
            # with trio.move_on_after(self.config.retry_timeout_milli/1000):
                async with trio.open_nursery() as nursery:
                    if read_only or self.primary is None:
                        await self.send_all(data)
                    else:
                        await self.send_to_primary(data)
                    nursery.start_soon(self.recvall, nursery)
            if self.reply is None:
                self.reset_on_retry()
        return self.reply

    async def send_to_primary(self, request):
        """Send a serialized request to the primary"""
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self.sendto, request, self.primary.id)

    async def send_all(self, request):
        """Send a serialized request to all replicas"""
        async with trio.open_nursery() as nursery:
            for replica in self.replicas:
                nursery.start_soon(self.sendto, request, replica.id)

    async def sendto(self, request, id):
        """Send a request over a udp socket"""
        # data = bytearray()
        # data.extend(struct.pack('>i', len(request)))
        # data.extend(request)
        
        lenfmt = "<L0L"
        slen = struct.pack(lenfmt, len(request))
        data = b''.join([slen, request])
        print(f'Yehuda sendto packed {slen} {data} {len(request)}')
        print(f'Yehuda unpack {struct.unpack(lenfmt,slen)[0]}')

        # print(f'Yehuda utest pack {struct.pack(lenfmt,49)}')
        # print(f'Yehuda utest npack {struct.unpack(lenfmt,struct.pack(lenfmt,49))}')

        self.ssock[id].send(data)
        self.msgs_sent += 1


    async def recvit(self):
        data = self.ssock.recv(self.config.max_msg_size)
        return data

    async def recfrom(self,id):
        data = self.ssock.recv(self.config.max_msg_size)
        return data

    async def xxxrecv(self, cancel_scope):
        """
        Receive reply messages until a quorum is achieved or the enclosing
        cancel_scope times out.
        """
        # data = self.ssock.recv(self.config.max_msg_size)
        # header, reply = bft_msgs.unpack_reply(data)
        # if self.valid_reply(header):
        #     self.replies[self.primary.id] = (header, reply)
        #     self.reply = (header, reply)
        # cancel_scope.cancel()

        while True:
            data, sender = await self.sock.recvfrom(self.config.max_msg_size)
            header, reply = bft_msgs.unpack_reply(data)
            if self.valid_reply(header):
                self.replies[sender] = (header, reply)
            if self.has_quorum():
                # This cancel will propagate up ward and gracefully terminate all
                # coroutines. self.reply will get set in self.has_quorum()
                cancel_scope.cancel()

    async def recvall(self, nursery):
        send_channel, receive_channel = trio.open_memory_channel(0)

        async def recfrom(rid):
            data = self.ssock[rid].recv(self.config.max_msg_size)
            await send_channel.send((data, rid))

        for rid in self.ssock.keys():
            nursery.start_soon(recfrom,rid)

        while True:
            data, sender = await receive_channel.receive()
            if len(data) > 0: 
                header, reply = bft_msgs.unpack_reply(data)
                if self.valid_reply(header):
                    self.replies[sender] = (header, reply)
                    if self.has_quorum():
                        nursery.cancel_scope.cancel()
            nursery.start_soon(recfrom,sender)

    def valid_reply(self, header):
        """Return true if the sequence number is correct"""
        return self.req_seq_num.val() == header.req_seq_num

    def has_quorum(self):
        """
        Return true if the client has seen 2F+C+1 matching replies

        Side Effects:
            Set self.reply to the reply with the quorum
            Set self.primary to the primary in the quorum of reply headers
        """

        if len(self.replies) < self.reply_quorum:
            return False

        # a reply mapped to a count of each specific reply
        # We must have a quorum of identical replies
        reply_counts = dict()
        for reply in self.replies.values():
            count = reply_counts.get(reply, 0)
            reply_counts[reply] = count + 1

        for reply, counts in reply_counts.items():
            if counts >= self.reply_quorum:
                self.reply = reply[1]
                self.primary = self.replicas[reply[0].primary_id]
                return True
        return False
