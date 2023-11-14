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

from base64 import b64decode
from unittest.mock import mock_open, patch

import pytest

from ssb.util import ConfigException, load_ssb_secret

CONFIG_FILE = """
## Comments should be supported too
{
    "curve": "ed25519",
    "public": "rsYpBIcXsxjQAf0JNes+MHqT2DL+EfopWKAp4rGeEPQ=ed25519",
    "private": "/bqDBI/vGLD5qy3GxMsgHFgYIrrY08JfTzUaCYT6x0GuxikEhxezGNAB/Qk16z4wepPYMv4R+ilYoCnisZ4Q9A==",
    "id": "@rsYpBIcXsxjQAf0JNes+MHqT2DL+EfopWKAp4rGeEPQ=.ed25519"
}
"""

CONFIG_FILE_INVALID = CONFIG_FILE.replace("ed25519", "foo")


def test_load_secret():
    with patch("ssb.util.open", mock_open(read_data=CONFIG_FILE), create=True):
        secret = load_ssb_secret()

    priv_key = b'\xfd\xba\x83\x04\x8f\xef\x18\xb0\xf9\xab-\xc6\xc4\xcb \x1cX\x18"\xba\xd8\xd3\xc2_O5\x1a\t\x84\xfa\xc7A'

    assert secret["id"] == "@rsYpBIcXsxjQAf0JNes+MHqT2DL+EfopWKAp4rGeEPQ=.ed25519"
    assert bytes(secret["keypair"]) == priv_key
    assert bytes(secret["keypair"].verify_key) == b64decode("rsYpBIcXsxjQAf0JNes+MHqT2DL+EfopWKAp4rGeEPQ=")


def test_load_exception():
    with pytest.raises(ConfigException):
        with patch("ssb.util.open", mock_open(read_data=CONFIG_FILE_INVALID), create=True):
            load_ssb_secret()
