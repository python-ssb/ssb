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

"""MuxRPC"""

from async_generator import async_generator, yield_

from ssb.packet_stream import PSMessageType


class MuxRPCAPIException(Exception):
    """Exception to raise on MuxRPC API errors"""


class MuxRPCHandler:  # pylint: disable=too-few-public-methods
    """Base MuxRPC handler class"""

    def check_message(self, msg):
        """Check message validity"""

        body = msg.body

        if isinstance(body, dict) and "name" in body and body["name"] == "Error":
            raise MuxRPCAPIException(body["message"])


class MuxRPCRequestHandler(MuxRPCHandler):
    """MuxRPC handler for incoming RPC requests"""

    def __init__(self, ps_handler):
        self.ps_handler = ps_handler

    def __await__(self):
        msg = yield from self.ps_handler.__await__()
        self.check_message(msg)
        return msg


class MuxRPCSourceHandler(MuxRPCHandler):
    """MuxRPC handler for source-type RPC requests"""

    def __init__(self, ps_handler):
        self.ps_handler = ps_handler

    @async_generator
    async def __aiter__(self):
        async for msg in self.ps_handler:
            self.check_message(msg)
            await yield_(msg)


class MuxRPCSinkHandlerMixin:  # pylint: disable=too-few-public-methods
    """Mixin for sink-type MuxRPC handlers"""

    def send(self, msg, msg_type=PSMessageType.JSON, end=False):
        """Send a message through the stream"""

        self.connection.send(msg, stream=True, msg_type=msg_type, req=self.req, end_err=end)


class MuxRPCDuplexHandler(MuxRPCSinkHandlerMixin, MuxRPCSourceHandler):
    """MuxRPC handler for duplex streams"""

    def __init__(self, ps_handler, connection, req):
        super().__init__(ps_handler)

        self.connection = connection
        self.req = req


class MuxRPCSinkHandler(MuxRPCHandler, MuxRPCSinkHandlerMixin):
    """MuxRPC handler for sinks"""

    def __init__(self, connection, req):
        self.connection = connection
        self.req = req


def _get_appropriate_api_handler(type_, connection, ps_handler, req):
    """Find the appropriate MuxRPC handler"""

    if type_ in {"sync", "async"}:
        return MuxRPCRequestHandler(ps_handler)

    if type_ == "source":
        return MuxRPCSourceHandler(ps_handler)

    if type_ == "sink":
        return MuxRPCSinkHandler(connection, req)

    if type_ == "duplex":
        return MuxRPCDuplexHandler(ps_handler, connection, req)

    return None


class MuxRPCRequest:
    """MuxRPC request"""

    @classmethod
    def from_message(cls, message):
        """Initialise a request from a raw packet stream message"""

        body = message.body

        return cls(".".join(body["name"]), body["args"])

    def __init__(self, name, args):
        self.name = name
        self.args = args

    def __repr__(self):
        return f"<MuxRPCRequest {self.name} {self.args}>"


class MuxRPCMessage:
    """MuxRPC message"""

    @classmethod
    def from_message(cls, message):
        """Initialise a MuxRPC message from a raw packet stream message"""

        return cls(message.body)

    def __init__(self, body):
        self.body = body

    def __repr__(self):
        return f"<MuxRPCMessage {self.body}>"


class MuxRPCAPI:
    """Generic MuxRPC API"""

    def __init__(self):
        self.handlers = {}
        self.connection = None

    async def __await__(self):
        async for req_message in self.connection:
            body = req_message.body
            if req_message is None:
                return
            if isinstance(body, dict) and body.get("name"):
                self.process(self.connection, MuxRPCRequest.from_message(req_message))

    def add_connection(self, connection):
        """Set the packet stream connection of this RPC API"""

        self.connection = connection

    def define(self, name):
        """Decorator to define an RPC method handler"""

        def _handle(f):
            self.handlers[name] = f

            return f

        return _handle

    def process(self, connection, request):
        """Process an incoming request"""

        handler = self.handlers.get(request.name)

        if not handler:
            raise MuxRPCAPIException(f"Method {request.name} not found!")

        handler(connection, request)

    def call(self, name, args, type_="sync"):
        """Call an RPC method"""

        if not self.connection.is_connected:
            raise Exception("not connected")  # pylint: disable=broad-exception-raised

        old_counter = self.connection.req_counter
        ps_handler = self.connection.send(
            {"name": name.split("."), "args": args, "type": type_},
            stream=type_ in {"sink", "source", "duplex"},
        )

        return _get_appropriate_api_handler(type_, self.connection, ps_handler, old_counter)
