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

"""Example SSB Client"""

from asyncio import ensure_future, gather, get_event_loop
import base64
import hashlib
import logging
import os
import struct
import time

from colorlog import ColoredFormatter
from nacl.signing import SigningKey, VerifyKey
from secret_handshake.network import SHSClient

from ssb.muxrpc import MuxRPCAPI, MuxRPCAPIException, MuxRPCDuplexHandler, MuxRPCRequest
from ssb.packet_stream import PacketStream, PSMessageType
from ssb.util import load_ssb_secret

api = MuxRPCAPI()
logger = logging.getLogger(__name__)


@api.define("createHistoryStream")
def create_history_stream(connection: PacketStream, msg: MuxRPCRequest) -> None:  # pylint: disable=unused-argument
    """Handle the createHistoryStream RPC call"""

    logger.info("create_history_stream %s", msg)
    # msg = PSMessage(PSMessageType.JSON, True, stream=True, end_err=True, req=-req)
    # connection.write(msg)


@api.define("blobs.createWants")
def create_wants(connection: PacketStream, msg: MuxRPCRequest) -> None:  # pylint: disable=unused-argument
    """Handle the createWants RPC call"""

    logger.info("create_wants %s", msg)


@api.define("isRoom")
def is_room(connection: PacketStream, msg: MuxRPCRequest) -> None:  # pylint: disable=unused-argument
    """Handle the isRoom RPC call"""

    logger.info("is_room %s", msg)


@api.define("room.metadata")
def room_metadata(connection: PacketStream, msg: MuxRPCRequest) -> None:  # pylint: disable=unused-argument
    """Handle the room.metadata RPC call"""

    logger.info("connection: %s", type(connection))
    logger.info("msg: %s", type(msg))

    logger.info("room_metadata: %s", msg)


async def test_client() -> None:
    """The actual client implementation"""

    async for msg in api.call(
        "createHistoryStream",
        [{"id": "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519", "seq": 1, "live": False, "keys": False}],
        "source",
    ):
        logger.info("> RESPONSE: %s", msg)

    try:
        response = api.call("whoami", [], "sync")
        logger.info("> RESPONSE: %s", await response.get_response())
    except MuxRPCAPIException as e:
        logger.error("MuxRPC error: %s", e)

    handler = api.call("gossip.ping", [], "duplex")
    assert isinstance(handler, MuxRPCDuplexHandler)

    handler.send(struct.pack("l", int(time.time() * 1000)), msg_type=PSMessageType.BUFFER)

    async for msg in handler:
        logger.info("> RESPONSE: %s", msg)
        handler.send(True, end=True)
        break

    img_data = b""
    handler = api.call("blobs.get", ["&kqZ52sDcJSHOx7m4Ww80kK1KIZ65gpGnqwZlfaIVWWM=.sha256"], "source")
    assert handler
    async for msg in handler:
        assert msg

        if msg.type.name == "BUFFER":
            img_data += msg.data
        if msg.type.name == "JSON" and msg.data == b"true":
            assert (
                base64.b64encode(hashlib.sha256(img_data).digest()) == b"kqZ52sDcJSHOx7m4Ww80kK1KIZ65gpGnqwZlfaIVWWM="
            )

            with open("./ub1k.jpg", "wb") as f:
                f.write(img_data)


async def main(keypair: SigningKey, server_key: VerifyKey) -> None:
    """The main function to run"""

    client = SHSClient("127.0.0.1", 8008, keypair, bytes(server_key))
    packet_stream = PacketStream(client)
    await client.open()
    api.add_connection(packet_stream)
    await gather(ensure_future(api.process_messages()), test_client())


if __name__ == "__main__":
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # create formatter
    formatter = ColoredFormatter(
        "%(log_color)s%(levelname)s%(reset)s:%(bold_white)s%(name)s%(reset)s - %(cyan)s%(message)s%(reset)s"
    )

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.setLevel(logging.INFO)
    logger.addHandler(ch)

    client_keypair = load_ssb_secret(os.path.expanduser("~/.ssb/notebook-secret"))["keypair"]
    outside_server_key = load_ssb_secret(
        os.path.expanduser("~/.var/app/se.manyver.Manyverse/config/manyverse/ssb/secret")
    )["keypair"].verify_key

    loop = get_event_loop()
    loop.run_until_complete(main(client_keypair, outside_server_key))
    loop.close()
