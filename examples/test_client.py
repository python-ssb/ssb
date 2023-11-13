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
import time
from asyncio import get_event_loop, gather, ensure_future

from colorlog import ColoredFormatter

from secret_handshake.network import SHSClient
from ssb.muxrpc import MuxRPCAPI, MuxRPCAPIException
from ssb.packet_stream import PacketStream, PSMessageType
from ssb.util import load_ssb_secret

import hashlib
import base64


api = MuxRPCAPI()


@api.define("createHistoryStream")
def create_history_stream(connection, msg):
    print("create_history_stream", msg)
    # msg = PSMessage(PSMessageType.JSON, True, stream=True, end_err=True, req=-req)
    # connection.write(msg)


@api.define("blobs.createWants")
def create_wants(connection, msg):
    print("create_wants", msg)


async def test_client():
    async for msg in api.call(
        "createHistoryStream",
        [
            {
                "id": "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
                "seq": 1,
                "live": False,
                "keys": False,
            }
        ],
        "source",
    ):
        print("> RESPONSE:", msg)

    try:
        print("> RESPONSE:", await api.call("whoami", [], "sync"))
    except MuxRPCAPIException as e:
        print(e)

    handler = api.call("gossip.ping", [], "duplex")
    handler.send(struct.pack("l", int(time.time() * 1000)), msg_type=PSMessageType.BUFFER)

    async for msg in handler:
        print("> RESPONSE:", msg)
        handler.send(True, end=True)
        break

    img_data = b""
    async for msg in api.call("blobs.get", ["&kqZ52sDcJSHOx7m4Ww80kK1KIZ65gpGnqwZlfaIVWWM=.sha256"], "source"):
        if msg.type.name == "BUFFER":
            img_data += msg.data
        if msg.type.name == "JSON" and msg.data == b"true":
            assert (
                base64.b64encode(hashlib.sha256(img_data).digest()) == b"kqZ52sDcJSHOx7m4Ww80kK1KIZ65gpGnqwZlfaIVWWM="
            )

            with open("./ub1k.jpg", "wb") as f:
                f.write(img_data)


async def main():
    client = SHSClient("127.0.0.1", 8008, keypair, bytes(keypair.verify_key))
    packet_stream = PacketStream(client)
    await client.open()
    api.add_connection(packet_stream)
    await gather(ensure_future(api), test_client())


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
    logger = logging.getLogger("packet_stream")
    logger.setLevel(logging.INFO)
    logger.addHandler(ch)

    keypair = load_ssb_secret()["keypair"]

    loop = get_event_loop()
    loop.run_until_complete(main())
    loop.close()
