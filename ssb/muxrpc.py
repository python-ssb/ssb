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

from typing import Any, AsyncIterator, Callable, Dict, List, Literal, Optional, Union

from typing_extensions import Self

from .packet_stream import PacketStream, PSMessage, PSMessageType, PSRequestHandler, PSStreamHandler

MuxRPCJSON = Dict[str, Any]
MuxRPCCallType = Literal["async", "duplex", "sink", "source", "sync"]
MuxRPCRequestHandlerType = Callable[[PacketStream, "MuxRPCRequest"], None]
MuxRPCRequestParam = Union[bytes, str, MuxRPCJSON]  # pylint: disable=invalid-name


class MuxRPCAPIException(Exception):
    """Exception to raise on MuxRPC API errors"""


class MuxRPCHandler:  # pylint: disable=too-few-public-methods
    """Base MuxRPC handler class"""

    def check_message(self, msg: PSMessage) -> None:
        """Check message validity"""

        body = msg.body

        if isinstance(body, dict) and "name" in body and body["name"] == "Error":
            raise MuxRPCAPIException(body["message"])

    def __aiter__(self) -> AsyncIterator[Optional[PSMessage]]:
        raise NotImplementedError()

    async def __anext__(self) -> Optional[PSMessage]:
        raise NotImplementedError()

    def send(self, msg: Any, msg_type: PSMessageType = PSMessageType.JSON, end: bool = False) -> None:
        """Send a message through the stream"""

        raise NotImplementedError()

    async def get_response(self) -> PSMessage:
        """Get the response for an RPC request"""

        raise NotImplementedError()


class MuxRPCRequestHandler(MuxRPCHandler):  # pylint: disable=abstract-method
    """MuxRPC handler for incoming RPC requests"""

    def __init__(self, ps_handler: PSRequestHandler):
        self.ps_handler = ps_handler

    async def get_response(self) -> PSMessage:
        """Get the response data"""

        msg = await self.ps_handler.__anext__()

        self.check_message(msg)

        return msg


class MuxRPCSourceHandler(MuxRPCHandler):  # pylint: disable=abstract-method
    """MuxRPC handler for source-type RPC requests"""

    def __init__(self, ps_handler: PSStreamHandler):
        self.ps_handler = ps_handler

    def __aiter__(self) -> AsyncIterator[Optional[PSMessage]]:
        return self

    async def __anext__(self) -> Optional[PSMessage]:
        msg = await self.ps_handler.__anext__()

        assert msg

        self.check_message(msg)

        return msg


class MuxRPCSinkHandlerMixin:  # pylint: disable=too-few-public-methods
    """Mixin for sink-type MuxRPC handlers"""

    connection: PacketStream
    req: int

    def send(self, msg: Any, msg_type: PSMessageType = PSMessageType.JSON, end: bool = False) -> None:
        """Send a message through the stream"""

        self.connection.send(msg, stream=True, msg_type=msg_type, req=self.req, end_err=end)


class MuxRPCDuplexHandler(MuxRPCSinkHandlerMixin, MuxRPCSourceHandler):  # pylint: disable=abstract-method
    """MuxRPC handler for duplex streams"""

    def __init__(self, ps_handler: PSStreamHandler, connection: PacketStream, req: int):
        super().__init__(ps_handler)

        self.connection = connection
        self.req = req


class MuxRPCSinkHandler(MuxRPCHandler, MuxRPCSinkHandlerMixin):  # pylint: disable=abstract-method
    """MuxRPC handler for sinks"""

    def __init__(self, connection: PacketStream, req: int):
        self.connection = connection
        self.req = req


def _get_appropriate_api_handler(
    type_: MuxRPCCallType, connection: PacketStream, ps_handler: Union[PSRequestHandler, PSStreamHandler], req: int
) -> MuxRPCHandler:
    """Find the appropriate MuxRPC handler"""

    if type_ in {"sync", "async"}:
        assert isinstance(ps_handler, PSRequestHandler)
        return MuxRPCRequestHandler(ps_handler)

    if type_ == "source":
        assert isinstance(ps_handler, PSStreamHandler)
        return MuxRPCSourceHandler(ps_handler)

    if type_ == "sink":
        return MuxRPCSinkHandler(connection, req)

    if type_ == "duplex":
        assert isinstance(ps_handler, PSStreamHandler)
        return MuxRPCDuplexHandler(ps_handler, connection, req)

    raise TypeError(f"Unknown request type {type_}")


class MuxRPCRequest:
    """MuxRPC request"""

    @classmethod
    def from_message(cls, message: PSMessage) -> Self:
        """Initialise a request from a raw packet stream message"""

        body = message.body

        assert isinstance(body, dict)

        return cls(".".join(body["name"]), body["args"])

    def __init__(self, name: str, args: List[MuxRPCRequestParam]):
        self.name = name
        self.args = args

    def __repr__(self) -> str:
        return f"<MuxRPCRequest {self.name} {self.args}>"


class MuxRPCMessage:
    """MuxRPC message"""

    @classmethod
    def from_message(cls, message: PSMessage) -> Self:
        """Initialise a MuxRPC message from a raw packet stream message"""

        return cls(message.body)

    def __init__(self, body: Union[bytes, str, Dict[str, Any], bool]):
        self.body = body

    def __repr__(self) -> str:
        return f"<MuxRPCMessage {self.body!r}>"


class MuxRPCAPI:
    """Generic MuxRPC API"""

    def __init__(self) -> None:
        self.handlers: Dict[str, MuxRPCRequestHandlerType] = {}
        self.connection: Optional[PacketStream] = None

    async def process_messages(self) -> None:
        """Continuously process incoming messages"""

        assert self.connection

        async for req_message in self.connection:
            if req_message is None:
                return

            body = req_message.body

            if isinstance(body, dict) and body.get("name"):
                self.process(self.connection, MuxRPCRequest.from_message(req_message))

    def add_connection(self, connection: PacketStream) -> None:
        """Set the packet stream connection of this RPC API"""

        self.connection = connection

    def define(self, name: str) -> Callable[[MuxRPCRequestHandlerType], MuxRPCRequestHandlerType]:
        """Decorator to define an RPC method handler"""

        def _handle(f: MuxRPCRequestHandlerType) -> MuxRPCRequestHandlerType:
            self.handlers[name] = f

            return f

        return _handle

    def process(self, connection: PacketStream, request: MuxRPCRequest) -> None:
        """Process an incoming request"""

        handler = self.handlers.get(request.name)

        if not handler:
            raise MuxRPCAPIException(f"Method {request.name} not found!")

        handler(connection, request)

    def call(self, name: str, args: List[MuxRPCRequestParam], type_: MuxRPCCallType = "sync") -> MuxRPCHandler:
        """Call an RPC method"""

        assert self.connection

        if not self.connection.is_connected:
            raise Exception("not connected")  # pylint: disable=broad-exception-raised

        old_counter = self.connection.req_counter
        ps_handler = self.connection.send(
            {"name": name.split("."), "args": args, "type": type_},
            stream=type_ in {"sink", "source", "duplex"},
        )

        return _get_appropriate_api_handler(type_, self.connection, ps_handler, old_counter)
