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
from asyncio import gather, get_event_loop, ensure_future

from colorlog import ColoredFormatter

from secret_handshake import SHSServer
from ssb.packet_stream import PacketStream
from ssb.muxrpc import MuxRPCAPI
from ssb.util import load_ssb_secret

api = MuxRPCAPI()


async def on_connect(conn):
    packet_stream = PacketStream(conn)
    api.add_connection(packet_stream)

    print("connect", conn)
    async for msg in packet_stream:
        print(msg)


async def main():
    server = SHSServer("127.0.0.1", 8008, load_ssb_secret()["keypair"])
    server.on_connect(on_connect)
    await server.listen()


if __name__ == "__main__":
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = ColoredFormatter(
        "%(log_color)s%(levelname)s%(reset)s:%(bold_white)s%(name)s%(reset)s - " "%(cyan)s%(message)s%(reset)s"
    )

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger = logging.getLogger("packet_stream")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    loop = get_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()
    loop.close()
