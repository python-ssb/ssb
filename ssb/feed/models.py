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

"""Feed models"""

from base64 import b64encode
from collections import OrderedDict, namedtuple
from datetime import datetime
from hashlib import sha256
from typing import Any, Dict, Optional

from nacl.signing import SigningKey, VerifyKey
from simplejson import dumps, loads
from typing_extensions import Self

from ssb.util import tag

OrderedMsg = namedtuple("OrderedMsg", ("previous", "author", "sequence", "timestamp", "hash", "content"))


class NoPrivateKeyException(Exception):
    """Exception to raise when a private key is not available"""


def to_ordered(data: Dict[str, Any]) -> OrderedDict[str, Any]:
    """Convert a dictionary to an ``OrderedDict``"""

    smsg = OrderedMsg(**data)

    return OrderedDict((k, getattr(smsg, k)) for k in smsg._fields)


def get_millis_1970() -> int:
    """Get the UNIX timestamp in milliseconds"""

    return int(datetime.utcnow().timestamp() * 1000)


class Feed:
    """Base class for feeds"""

    def __init__(self, public_key: VerifyKey):
        self.public_key = public_key

    @property
    def id(self) -> str:
        """The identifier of the feed"""

        return tag(self.public_key).decode("ascii")

    def sign(self, msg: bytes) -> bytes:
        """Sign a message"""

        raise NoPrivateKeyException("Cannot use remote identity to sign (no private key!)")


class LocalFeed(Feed):
    """Class representing a local feed"""

    def __init__(self, private_key: SigningKey):  # pylint: disable=super-init-not-called
        self.private_key = private_key

    @property
    def public_key(self) -> VerifyKey:
        """The public key of the feed"""

        return self.private_key.verify_key

    @public_key.setter
    def public_key(self, key: VerifyKey) -> None:
        raise TypeError("Can not set only the public key for a local feed")

    def sign(self, msg: bytes) -> bytes:
        """Sign a message for this feed"""

        return self.private_key.sign(msg).signature


class Message:
    """Base class for SSB messages"""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        feed: Feed,
        content: Dict[str, Any],
        signature: Optional[str] = None,
        sequence: int = 1,
        timestamp: Optional[int] = None,
        previous: Optional["Message"] = None,
    ):
        self.feed = feed
        self.content = content
        self.signature = signature
        self.previous = previous
        self.timestamp = get_millis_1970() if timestamp is None else timestamp

        if self.previous:
            self.sequence: int = self.previous.sequence + 1
        else:
            self.sequence = sequence

        self._check_signature()

    def _check_signature(self) -> None:
        if self.signature is None:
            raise ValueError("signature can't be None")

    @classmethod
    def parse(cls, data: bytes, feed: Feed) -> Self:
        """Parse raw message data"""

        obj = loads(data, object_pairs_hook=OrderedDict)
        msg = cls(feed, obj["content"], timestamp=obj["timestamp"])

        return msg

    def serialize(self, add_signature: bool = True) -> bytes:
        """Serialize the message"""

        return dumps(self.to_dict(add_signature=add_signature), indent=2).encode("utf-8")

    def to_dict(self, add_signature: bool = True) -> OrderedDict[str, Any]:
        """Convert the message to a dictionary"""

        obj = to_ordered(
            {
                "previous": self.previous.key if self.previous else None,
                "author": self.feed.id,
                "sequence": self.sequence,
                "timestamp": self.timestamp,
                "hash": "sha256",
                "content": self.content,
            }
        )

        if add_signature:
            obj["signature"] = self.signature

        return obj

    def verify(self, signature: str) -> bool:
        """Verify the signature of the message"""

        return self.signature == signature

    @property
    def hash(self) -> str:
        """The cryptographic hash of the message"""

        hash_ = sha256(self.serialize()).digest()

        return b64encode(hash_).decode("ascii") + ".sha256"

    @property
    def key(self) -> str:
        """The key of the message"""

        return "%" + self.hash


class LocalMessage(Message):
    """Class representing a local message"""

    def __init__(  # pylint: disable=too-many-arguments,super-init-not-called
        self,
        feed: LocalFeed,
        content: Dict[str, Any],
        signature: Optional[str] = None,
        sequence: int = 1,
        timestamp: Optional[int] = None,
        previous: Optional["LocalMessage"] = None,
    ):
        super().__init__(feed, content, signature=signature, sequence=sequence, timestamp=timestamp, previous=previous)

    def _check_signature(self) -> None:
        if self.signature is None:
            self.signature = self._sign()

    def _sign(self) -> str:
        # ensure ordering of keys and indentation of 2 characters, like ssb-keys
        data = self.serialize(add_signature=False)

        return (b64encode(bytes(self.feed.sign(data))) + b".sig.ed25519").decode("ascii")
