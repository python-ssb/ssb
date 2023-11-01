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

"""Utility functions"""

from base64 import b64decode, b64encode
import os
from typing import Optional, TypedDict

from nacl.signing import SigningKey, VerifyKey
import yaml


class SSBSecret(TypedDict):
    """Dictionary to hold an SSB identity"""

    keypair: SigningKey
    id: str


class ConfigException(Exception):
    """Exception to raise if there is a problem with the configuration data"""


def tag(key: VerifyKey) -> bytes:
    """Create tag from public key"""

    return b"@" + b64encode(bytes(key)) + b".ed25519"


def load_ssb_secret(filename: Optional[str] = None) -> SSBSecret:
    """Load SSB keys from ``filename`` or, if unset, from ``~/.ssb/secret``"""

    filename = filename or os.path.expanduser("~/.ssb/secret")

    with open(filename, encoding="utf-8") as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    if config["curve"] != "ed25519":
        raise ConfigException("Algorithm not known: " + config["curve"])

    server_prv_key = b64decode(config["private"][:-8])
    return {"keypair": SigningKey(server_prv_key[:32]), "id": config["id"]}
