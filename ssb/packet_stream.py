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

"""Packet streams"""

from asyncio import Event, Queue
from enum import Enum
import logging
from math import ceil
import struct
from time import time
from typing import Any, AsyncIterator, Dict, Optional, Tuple, Union

from secret_handshake.network import SHSDuplexStream
import simplejson
from typing_extensions import Self

PSHandler = Union["PSRequestHandler", "PSStreamHandler"]
PSMessageData = Union[bytes, bool, Dict[str, Any], str]
logger = logging.getLogger("packet_stream")


class PSMessageType(Enum):
    """Available message types"""

    BUFFER = 0
    TEXT = 1
    JSON = 2


class PSStreamHandler:
    """Packet stream handler"""

    def __init__(self, req: int):
        self.req = req
        self.queue: Queue["PSMessage"] = Queue()

    async def process(self, msg: "PSMessage") -> None:
        """Process a pending message"""

        await self.queue.put(msg)

    async def stop(self) -> None:
        """Stop a pending request"""

        # We use the None value internally to signal __anext__ that the stream can be closed.  It is not used otherwise,
        # hence the typing ignore
        await self.queue.put(None)  # type: ignore[arg-type]

    def __aiter__(self) -> AsyncIterator[Optional["PSMessage"]]:
        return self

    async def __anext__(self) -> Optional["PSMessage"]:
        elem = await self.queue.get()

        if not elem:
            raise StopAsyncIteration()

        return elem


class PSRequestHandler:
    """Packet stream request handler"""

    def __init__(self, req: int):
        self.req = req
        self.event = Event()
        self._msg: Optional["PSMessage"] = None

    async def process(self, msg: "PSMessage") -> None:
        """Process a message request"""

        self._msg = msg
        self.event.set()

    async def stop(self) -> None:
        """Stop a pending event request"""

        if not self.event.is_set():
            self.event.set()

    def __aiter__(self) -> AsyncIterator["PSMessage"]:
        return self

    async def __anext__(self) -> "PSMessage":
        # wait until 'process' is called
        await self.event.wait()

        assert self._msg

        return self._msg


class PSMessage:
    """Packet Stream message"""

    @classmethod
    def from_header_body(cls, flags: int, req: int, body: bytes) -> Self:
        """Parse a raw message"""

        type_ = PSMessageType(flags & 0x03)

        if type_ == PSMessageType.TEXT:
            decoded_body: Union[str, Dict[str, Any], bytes] = body.decode("utf-8")
        elif type_ == PSMessageType.JSON:
            decoded_body = simplejson.loads(body)
        else:
            decoded_body = body

        return cls(type_, decoded_body, bool(flags & 0x08), bool(flags & 0x04), req=req)

    @property
    def data(self) -> bytes:
        """The raw message data"""

        if self.body is True:
            return b"true"

        if self.type == PSMessageType.TEXT:
            assert isinstance(self.body, str)

            return self.body.encode("utf-8")

        if self.type == PSMessageType.JSON:
            assert isinstance(self.body, dict)
            return simplejson.dumps(self.body).encode("utf-8")

        assert isinstance(self.body, bytes)

        return self.body

    def __init__(
        self,
        type_: PSMessageType,
        body: Union[bytes, str, Dict[str, Any], bool],
        stream: bool,
        end_err: bool,
        req: Optional[int] = None,
    ):  # pylint: disable=too-many-arguments
        self.stream = stream
        self.end_err = end_err
        self.type = type_
        self.body = body
        self.req = req

    def __repr__(self) -> str:
        if self.body is True:
            body = "EOF"
        elif self.type == PSMessageType.BUFFER:
            assert isinstance(self.body, bytes)
            body = f"{len(self.body)} bytes"
        else:
            body = str(self.body)

        req = "" if self.req is None else f" [{self.req}]"
        is_stream = "~" if self.stream else ""
        err = "!" if self.end_err else ""

        return f"<PSMessage ({self.type.name}): {body}{req} {is_stream}{err}>"


class PacketStream:
    """SSB Packet stream"""

    def __init__(self, connection: SHSDuplexStream):
        self.connection = connection
        self.req_counter = 1
        self._event_map: Dict[int, Tuple[float, PSHandler]] = {}
        self._connected = False

    def register_handler(self, handler: PSHandler) -> None:
        """Register an RPC handler"""

        self._event_map[handler.req] = (time(), handler)

    @property
    def is_connected(self) -> bool:
        """Check if the stream is connected"""

        return self.connection.is_connected

    def __aiter__(self) -> AsyncIterator[Optional[PSMessage]]:
        return self

    async def __anext__(self) -> PSMessage:
        while True:
            msg = await self.read()

            if not msg:
                raise StopAsyncIteration()

            if msg.req is not None and msg.req >= 0:
                logger.info("RECV: %r", msg)

                return msg

    async def _read(self) -> Optional[PSMessage]:
        try:
            header = await self.connection.read()

            if not header or header == b"\x00" * 9:
                return None

            flags, length, req = struct.unpack(">BIi", header)
            n_packets = ceil(length / 4096)
            body = b""

            for _ in range(n_packets):
                read_data = await self.connection.read()

                if not read_data:
                    logger.debug("DISCONNECT")
                    self.connection.close()

                    return None

                body += read_data

            logger.debug("READ %s %s", header, len(body))

            return PSMessage.from_header_body(flags, req, body)
        except StopAsyncIteration:
            logger.debug("DISCONNECT")
            self.connection.close()

            return None

    async def read(self) -> Optional[PSMessage]:
        """Read data from the packet stream"""

        msg = await self._read()

        if not msg:
            return None

        # check whether it's a reply and handle accordingly
        if msg.req is not None and msg.req < 0:
            _, handler = self._event_map[-msg.req]
            await handler.process(msg)
            logger.info("RESPONSE [%d]: %r", -msg.req, msg)

            if msg.end_err:
                await handler.stop()
                del self._event_map[-msg.req]
                logger.info("RESPONSE [%d]: EOS", -msg.req)

        return msg

    def _write(self, msg: PSMessage) -> None:
        logger.info("SEND [%d]: %r", msg.req, msg)
        header = struct.pack(
            ">BIi",
            (int(msg.stream) << 3) | (int(msg.end_err) << 2) | msg.type.value,
            len(msg.data),
            msg.req,
        )
        self.connection.write(header)
        self.connection.write(msg.data)
        logger.debug("WRITE HDR: %s", header)
        logger.debug("WRITE DATA: %s", msg.data)

    def send(  # pylint: disable=too-many-arguments
        self,
        data: Union[bytes, str, Dict[str, Any]],
        msg_type: PSMessageType = PSMessageType.JSON,
        stream: bool = False,
        end_err: bool = False,
        req: Optional[int] = None,
    ) -> PSHandler:
        """Send data through the packet stream"""

        update_counter = False

        if req is None:
            update_counter = True
            req = self.req_counter

        msg = PSMessage(msg_type, data, stream=stream, end_err=end_err, req=req)

        # send request
        self._write(msg)

        if stream:
            handler: PSHandler = PSStreamHandler(self.req_counter)
        else:
            handler = PSRequestHandler(self.req_counter)

        self.register_handler(handler)

        if update_counter:
            self.req_counter += 1

        return handler

    def disconnect(self) -> None:
        """Disconnect the stream"""

        self._connected = False
        self.connection.close()
