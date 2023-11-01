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

import os
import yaml
from base64 import b64decode, b64encode

from nacl.signing import SigningKey


class ConfigException(Exception):
    pass


def tag(key):
    """Create tag from publick key."""
    return b"@" + b64encode(bytes(key)) + b".ed25519"


def load_ssb_secret():
    """Load SSB keys from ~/.ssb"""
    with open(os.path.expanduser("~/.ssb/secret")) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    if config["curve"] != "ed25519":
        raise ConfigException("Algorithm not known: " + config["curve"])

    server_prv_key = b64decode(config["private"][:-8])
    return {"keypair": SigningKey(server_prv_key[:32]), "id": config["id"]}
