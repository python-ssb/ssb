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

"""Tests for the packet stream"""

from asyncio import Event, ensure_future, gather
from asyncio.events import AbstractEventLoop
import json
from typing import Awaitable, Callable, Generator, List, Optional, Union

import pytest
from pytest_mock import MockerFixture
from secret_handshake.network import SHSDuplexStream

from ssb.packet_stream import PacketStream, PSMessage, PSMessageType, PSRequestHandler, PSStreamHandler


async def _collect_messages(
    generator: Union[PSRequestHandler, PSStreamHandler, PacketStream]
) -> List[Optional[PSMessage]]:
    results = []

    async for msg in generator:  # pragma: no branch
        results.append(msg)

    return results


MSG_BODY_1 = (
    b'{"previous":"%KTGP6W8vF80McRAZHYDWuKOD0KlNyKSq6Gb42iuV7Iw=.sha256","author":"@1+Iwm79DKvVBqYKFkhT6fWRbA'
    b'VvNNVH4F2BSxwhYmx8=.ed25519","sequence":116,"timestamp":1496696699331,"hash":"sha256","content":{"type"'
    b':"post","channel":"crypto","text":"Does anybody know any good resources (e.g. books) to learn cryptogra'
    b"phy? I'm not speaking of basic concepts (e.g. what's a private key) but the actual mathematics behind"
    b' the whole thing.\\nI have a copy of the \\"Handbook of Applied Cryptography\\" on my bookshelf but I f'
    b'ound it too long/hard to follow. Are there any better alternatives?","mentions":[]},"signature":"hqKePb'
    b'bTXWxEi1njDnOWFsL0M0AoNoWyBFgNE6KXj//DThepaZSy9vRbygDHX5uNmCdyOrsQrwZsZhmUYKwtDQ==.sig.ed25519"}'
)

MSG_BODY_2 = (
    b'{"previous":"%iQRhPyqmNLpGaO1Tpm1I22jqnUEwRwkCTDbwAGtM+lY=.sha256","author":"@1+Iwm79DKvVBqYKFkhT6fWRbA'
    b'VvNNVH4F2BSxwhYmx8=.ed25519","sequence":103,"timestamp":1496674211806,"hash":"sha256","content":{"type"'
    b':"post","channel":"git-ssb","text":"Is it only me or `git.scuttlebot.io` is timing out?\\n\\nE.g. try a'
    b'ccessing %vZCTqraoqKBKNZeATErXEtnoEr+wnT3p8tT+vL+29I4=.sha256","mentions":[{"link":"%vZCTqraoqKBKNZeATE'
    b'rXEtnoEr+wnT3p8tT+vL+29I4=.sha256"}]},"signature":"+i4U0HUGDDEyNoNr2NIROPnT3WQj3RuTaIhY5koWW8f0vwr4tZsY'
    b'mAkqqMwFWfP+eBIbc7DZ835er6r6h9CwAg==.sig.ed25519"}'
)


class MockSHSSocket(SHSDuplexStream):
    """A mocked SHS socket"""

    def __init__(self) -> None:  # pylint: disable=unused-argument
        super().__init__()

        self.input: List[bytes] = []
        self.output: List[bytes] = []
        self.is_connected = False
        self._on_connect: List[Callable[[SHSDuplexStream], Awaitable[None]]] = []

    def on_connect(self, cb: Callable[[SHSDuplexStream], Awaitable[None]]) -> None:
        """Set the on_connect callback"""

        self._on_connect.append(cb)

    async def read(self) -> bytes:
        """Read data from the socket"""

        if not self.input:
            raise StopAsyncIteration

        return self.input.pop(0)

    def write(self, data: bytes) -> None:
        """Write data to the socket"""

        self.output.append(data)

    def feed(self, input_: List[bytes]) -> None:
        """Feed data into the connection"""

        self.input += input_

    def get_output(self) -> Generator[bytes, None, None]:
        """Get the output of a call"""

        while True:
            if not self.output:
                break

            yield self.output.pop(0)


class MockSHSClient(MockSHSSocket):
    """A mocked SHS client"""

    async def connect(self) -> None:
        """Connect to a SHS server"""

        self.is_connected = True


class MockSHSServer(MockSHSSocket):
    """A mocked SHS server"""

    def listen(self) -> None:
        """Listen for new connections"""

        self.is_connected = True

        for cb in self._on_connect:
            ensure_future(cb(self))


@pytest.fixture
def ps_client(event_loop: AbstractEventLoop) -> MockSHSClient:  # pylint: disable=unused-argument
    """Fixture to provide a mocked SHS client"""

    return MockSHSClient()


@pytest.fixture
def ps_server(event_loop: AbstractEventLoop) -> MockSHSServer:  # pylint: disable=unused-argument
    """Fixture to provide a mocked SHS server"""

    return MockSHSServer()


@pytest.mark.asyncio
async def test_on_connect(ps_server: MockSHSServer) -> None:  # pylint: disable=redefined-outer-name
    """Test the on_connect callback functionality"""

    called = Event()

    async def _on_connect(_: SHSDuplexStream) -> None:
        called.set()

    ps_server.on_connect(_on_connect)
    ps_server.listen()
    await called.wait()
    assert ps_server.is_connected


@pytest.mark.asyncio
async def test_message_decoding(ps_client: MockSHSClient) -> None:  # pylint: disable=redefined-outer-name
    """Test message decoding"""

    await ps_client.connect()

    ps = PacketStream(ps_client)

    assert ps.is_connected

    ps_client.feed(
        [
            b"\n\x00\x00\x00\x9a\x00\x00\x04\xfb",
            b'{"name":["createHistoryStream"],"args":[{"id":"@omgyp7Pnrw+Qm0I6T6Fh5VvnKmodMXwnxTIesW2DgMg=.ed25519",'
            b'"seq":10,"live":true,"keys":false}],"type":"source"}',
        ]
    )

    messages = await _collect_messages(ps)
    assert len(messages) == 1
    assert messages[0]
    assert messages[0].type == PSMessageType.JSON
    assert messages[0].body == {
        "name": ["createHistoryStream"],
        "args": [
            {
                "id": "@omgyp7Pnrw+Qm0I6T6Fh5VvnKmodMXwnxTIesW2DgMg=.ed25519",
                "seq": 10,
                "live": True,
                "keys": False,
            }
        ],
        "type": "source",
    }


@pytest.mark.asyncio
async def test_message_encoding(ps_client: MockSHSClient) -> None:  # pylint: disable=redefined-outer-name
    """Test message encoding"""

    await ps_client.connect()

    ps = PacketStream(ps_client)

    assert ps.is_connected

    ps.send(
        {
            "name": ["createHistoryStream"],
            "args": [
                {
                    "id": "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
                    "seq": 1,
                    "live": False,
                    "keys": False,
                }
            ],
            "type": "source",
        },
        stream=True,
    )

    header, body = list(ps_client.get_output())

    assert header == b"\x0a\x00\x00\x00\xa6\x00\x00\x00\x01"
    assert json.loads(body.decode("utf-8")) == {
        "name": ["createHistoryStream"],
        "args": [
            {
                "id": "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
                "seq": 1,
                "live": False,
                "keys": False,
            }
        ],
        "type": "source",
    }


@pytest.mark.asyncio
async def test_message_stream(
    ps_client: MockSHSClient, mocker: MockerFixture  # pylint: disable=redefined-outer-name
) -> None:
    """Test requesting a history stream"""

    await ps_client.connect()

    ps = PacketStream(ps_client)
    mocker.patch.object(ps, "register_handler", wraps=ps.register_handler)

    assert ps.is_connected

    ps.send(
        {
            "name": ["createHistoryStream"],
            "args": [
                {
                    "id": "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
                    "seq": 1,
                    "live": False,
                    "keys": False,
                }
            ],
            "type": "source",
        },
        stream=True,
    )

    assert ps.req_counter == 2
    assert ps.register_handler.call_count == 1  # type: ignore[attr-defined]  # pylint: disable=no-member
    handler = list(ps._event_map.values())[0][1]  # pylint: disable=protected-access
    mock_process = mocker.patch.object(handler, "process")

    ps_client.feed([b"\n\x00\x00\x02\xc5\xff\xff\xff\xff", MSG_BODY_1])
    msg = await ps.read()
    assert mock_process.await_count == 1

    # responses have negative req
    assert msg
    assert isinstance(msg.body, dict)
    assert msg.req == -1
    assert msg.body["previous"] == "%KTGP6W8vF80McRAZHYDWuKOD0KlNyKSq6Gb42iuV7Iw=.sha256"

    assert ps.req_counter == 2

    stream_handler = ps.send(
        {
            "name": ["createHistoryStream"],
            "args": [
                {
                    "id": "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
                    "seq": 1,
                    "live": False,
                    "keys": False,
                }
            ],
            "type": "source",
        },
        stream=True,
    )

    assert ps.req_counter == 3
    assert ps.register_handler.call_count == 2  # type: ignore[attr-defined]  # pylint: disable=no-member
    handler = list(ps._event_map.values())[1][1]  # pylint: disable=protected-access

    mock_process = mocker.patch.object(handler, "process", wraps=handler.process)

    ps_client.feed(
        [
            b"\n\x00\x00\x02\xc5\xff\xff\xff\xfe",
            MSG_BODY_1,
            b"\x0e\x00\x00\x023\xff\xff\xff\xfe",
            MSG_BODY_2,
        ]
    )

    # execute both message polling and response handling loops
    collected, handled = await gather(_collect_messages(ps), _collect_messages(stream_handler))

    # No messages collected, since they're all responses
    assert collected == []

    assert mock_process.call_count == 2

    for msg in handled:
        # responses have negative req
        assert msg
        assert msg.req == -2


@pytest.mark.asyncio
async def test_message_request(
    ps_server: MockSHSServer, mocker: MockerFixture  # pylint: disable=redefined-outer-name
) -> None:
    """Test message sending"""

    ps_server.listen()

    ps = PacketStream(ps_server)

    mocker.patch.object(ps, "register_handler", wraps=ps.register_handler)

    ps.send({"name": ["whoami"], "args": []})

    header, body = list(ps_server.get_output())
    assert header == b"\x02\x00\x00\x00 \x00\x00\x00\x01"
    assert json.loads(body.decode("utf-8")) == {"name": ["whoami"], "args": []}

    assert ps.req_counter == 2
    assert ps.register_handler.call_count == 1  # type: ignore[attr-defined]  # pylint: disable=no-member
    handler = list(ps._event_map.values())[0][1]  # pylint: disable=protected-access
    mock_process = mocker.patch.object(handler, "process")

    ps_server.feed(
        [
            b"\x02\x00\x00\x00>\xff\xff\xff\xff",
            b'{"id":"@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519"}',
        ]
    )
    msg = await ps.read()
    assert mock_process.await_count == 1

    # responses have negative req
    assert msg
    assert isinstance(msg.body, dict)
    assert msg.req == -1
    assert msg.body["id"] == "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519"
    assert ps.req_counter == 2
