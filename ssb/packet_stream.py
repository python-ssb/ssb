# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 PySSB contributors (see AUTHORS for more details)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
import struct
from asyncio import Event, Queue
from enum import Enum
from time import time
from math import ceil

import simplejson
from async_generator import async_generator, yield_

from secret_handshake import SHSClient, SHSServer


logger = logging.getLogger('packet_stream')


class PSMessageType(Enum):
    BUFFER = 0
    TEXT = 1
    JSON = 2


class PSStreamHandler(object):
    def __init__(self, req):
        super(PSStreamHandler).__init__()
        self.req = req
        self.queue = Queue()

    async def process(self, msg):
        await self.queue.put(msg)

    async def stop(self):
        await self.queue.put(None)

    @async_generator
    async def __aiter__(self):
        while True:
            elem = await self.queue.get()
            if not elem:
                return
            await yield_(elem)


class PSRequestHandler(object):
    def __init__(self, req):
        super(PSRequestHandler).__init__()
        self.req = req
        self.event = Event()
        self._msg = None

    async def process(self, msg):
        self._msg = msg
        self.event.set()

    async def stop(self):
        if not self.event.is_set():
            self.event.set()

    def __await__(self):
        # wait until 'process' is called
        yield from self.event.wait().__await__()
        return self._msg


class PSMessage(object):

    @classmethod
    def from_header_body(cls, flags, req, body):
        type_ = PSMessageType(flags & 0x03)

        if type_ == PSMessageType.TEXT:
            body = body.decode('utf-8')
        elif type_ == PSMessageType.JSON:
            body = simplejson.loads(body)

        return cls(type_, body, bool(flags & 0x08), bool(flags & 0x04), req=req)

    @property
    def data(self):
        if self.type == PSMessageType.TEXT:
            return self.body.encode('utf-8')
        elif self.type == PSMessageType.JSON:
            return simplejson.dumps(self.body).encode('utf-8')
        return self.body

    def __init__(self, type_, body, stream, end_err, req=None):
        self.stream = stream
        self.end_err = end_err
        self.type = type_
        self.body = body
        self.req = req

    def __repr__(self):
        if self.type == PSMessageType.BUFFER:
            body = '{} bytes'.format(len(self.body))
        else:
            body = self.body
        return '<PSMessage ({}): {}{} {}{}>'.format(self.type.name, body,
                                                    '' if self.req is None else ' [{}]'.format(self.req),
                                                    '~' if self.stream else '', '!' if self.end_err else '')


class PacketStream(object):
    def __init__(self, connection):
        self.connection = connection
        self.req_counter = 1
        self._event_map = {}

    def register_handler(self, handler):
        self._event_map[handler.req] = (time(), handler)

    @property
    def is_connected(self):
        return self.connection.is_connected

    @async_generator
    async def __aiter__(self):
        while True:
            msg = await self.read()
            if not msg:
                return
            # filter out replies
            if msg.req >= 0:
                await yield_(msg)

    async def __await__(self):
        async for data in self:
            logger.info('RECV: %r', data)
            if data is None:
                return

    async def _read(self):
        try:
            header = await self.connection.read()
            if not header or header == b'\x00' * 9:
                return
            flags, length, req = struct.unpack('>BIi', header)

            n_packets = ceil(length / 4096)

            body = b''
            for n in range(n_packets):
                body += await self.connection.read()

            logger.debug('READ %s %s', header, len(body))
            return PSMessage.from_header_body(flags, req, body)
        except StopAsyncIteration:
            logger.debug('DISCONNECT')
            self.connection.disconnect()
            return None

    async def read(self):
        msg = await self._read()
        if not msg:
            return None
        # check whether it's a reply and handle accordingly
        if msg.req < 0:
            t, handler = self._event_map[-msg.req]
            await handler.process(msg)
            logger.info('RESPONSE [%d]: %r', -msg.req, msg)
            if msg.end_err:
                await handler.stop()
                del self._event_map[-msg.req]
                logger.info('RESPONSE [%d]: EOS', -msg.req)
        return msg

    def _write(self, msg):
        logger.info('SEND [%d]: %r', msg.req, msg)
        header = struct.pack('>BIi', (int(msg.stream) << 3) | (int(msg.end_err) << 2) | msg.type.value, len(msg.data),
                             msg.req)
        self.connection.write(header)
        self.connection.write(msg.data)
        logger.debug('WRITE HDR: %s', header)
        logger.debug('WRITE DATA: %s', msg.data)

    def send(self, data, msg_type=PSMessageType.JSON, stream=False, end_err=False, req=None):
        update_counter = False
        if req is None:
            update_counter = True
            req = self.req_counter

        msg = PSMessage(msg_type, data, stream=stream, end_err=end_err, req=req)

        # send request
        self._write(msg)

        if stream:
            handler = PSStreamHandler(self.req_counter)
        else:
            handler = PSRequestHandler(self.req_counter)
        self.register_handler(handler)

        if update_counter:
            self.req_counter += 1
        return handler

    def disconnect(self):
        self._connected = False
        self.connection.disconnect()
