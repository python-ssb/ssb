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

"""Tests for the feed functionality"""

from base64 import b64decode
from collections import OrderedDict
from datetime import datetime, timezone

from nacl.signing import SigningKey, VerifyKey
import pytest
from pytest_mock import MockerFixture

from ssb.feed import Feed, LocalFeed, LocalMessage, Message, NoPrivateKeyException
from ssb.feed.models import get_millis_1970

SERIALIZED_M1 = b"""{
  "previous": null,
  "author": "@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519",
  "sequence": 1,
  "timestamp": 1495706260190,
  "hash": "sha256",
  "content": {
    "type": "about",
    "about": "@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519",
    "name": "neo",
    "description": "The Chosen One"
  },
  "signature": "lPsQ9P10OgeyH6u0unFgiI2wV/RQ7Q2x2ebxnXYCzsJ055TBMXphRADTKhOMS2EkUxXQ9k3amj5fnWPudGxwBQ==.sig.ed25519"
}"""


@pytest.fixture()
def local_feed() -> LocalFeed:
    """Fixture providing a local feed"""

    secret = b64decode("Mz2qkNOP2K6upnqibWrR+z8pVUI1ReA1MLc7QMtF2qQ=")
    return LocalFeed(SigningKey(secret))


@pytest.fixture()
def remote_feed() -> Feed:
    """Fixture providing a remote feed"""

    public = b64decode("I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=")
    return Feed(VerifyKey(public))


def test_local_feed() -> None:
    """Test a local feed"""

    secret = b64decode("Mz2qkNOP2K6upnqibWrR+z8pVUI1ReA1MLc7QMtF2qQ=")
    feed = LocalFeed(SigningKey(secret))
    assert bytes(feed.private_key) == secret
    assert bytes(feed.public_key) == b64decode("I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=")
    assert feed.id == "@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519"


def test_local_feed_set_pubkey(local_feed: LocalFeed) -> None:  # pylint: disable=redefined-outer-name
    """Test setting only the public key for a local feed"""

    key = SigningKey.generate().verify_key

    with pytest.raises(TypeError) as ctx:
        local_feed.public_key = key

    assert str(ctx.value) == "Can not set only the public key for a local feed"


def test_remote_feed() -> None:
    """Test a remote feed"""

    public = b64decode("I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=")
    feed = Feed(VerifyKey(public))
    assert bytes(feed.public_key) == public
    assert feed.id == "@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519"

    m1 = Message(
        feed,
        OrderedDict([("type", "about"), ("about", feed.id), ("name", "neo"), ("description", "The Chosen One")]),
        "foo",
        timestamp=1495706260190,
    )

    with pytest.raises(NoPrivateKeyException):
        feed.sign(m1.serialize())


def test_local_message(local_feed: LocalFeed) -> None:  # pylint: disable=redefined-outer-name
    """Test a local message"""

    m1 = LocalMessage(
        local_feed,
        OrderedDict([("type", "about"), ("about", local_feed.id), ("name", "neo"), ("description", "The Chosen One")]),
        timestamp=1495706260190,
    )
    assert m1.timestamp == 1495706260190
    assert m1.previous is None
    assert m1.sequence == 1
    assert (
        m1.signature
        == "lPsQ9P10OgeyH6u0unFgiI2wV/RQ7Q2x2ebxnXYCzsJ055TBMXphRADTKhOMS2EkUxXQ9k3amj5fnWPudGxwBQ==.sig.ed25519"
    )
    assert m1.key == "%xRDqws/TrQmOd4aEwZ32jdLhP873ZKjIgHlggPR0eoo=.sha256"

    m2 = LocalMessage(
        local_feed,
        OrderedDict(
            [
                ("type", "about"),
                ("about", local_feed.id),
                ("name", "morpheus"),
                ("description", "Dude with big jaw"),
            ]
        ),
        previous=m1,
        timestamp=1495706447426,
    )
    assert m2.timestamp == 1495706447426
    assert m2.previous is m1
    assert m2.sequence == 2
    assert (
        m2.signature
        == "3SY85LX6/ppOfP4SbfwZbKfd6DccbLRiB13pwpzbSK0nU52OEJxOqcJ2Uensr6RkrWztWLIq90sNOn1zRAoOAw==.sig.ed25519"
    )
    assert m2.key == "%nx13uks5GUwuKJC49PfYGMS/1pgGTtwwdWT7kbVaroM=.sha256"


def test_remote_message(remote_feed: Feed) -> None:  # pylint: disable=redefined-outer-name
    """Test a remote message"""

    signature = "lPsQ9P10OgeyH6u0unFgiI2wV/RQ7Q2x2ebxnXYCzsJ055TBMXphRADTKhOMS2EkUxXQ9k3amj5fnWPudGxwBQ==.sig.ed25519"
    m1 = Message(
        remote_feed,
        OrderedDict([("type", "about"), ("about", remote_feed.id), ("name", "neo"), ("description", "The Chosen One")]),
        signature,
        timestamp=1495706260190,
    )
    assert m1.timestamp == 1495706260190
    assert m1.previous is None
    assert m1.sequence == 1
    assert m1.signature == signature
    assert m1.key == "%xRDqws/TrQmOd4aEwZ32jdLhP873ZKjIgHlggPR0eoo=.sha256"

    signature = "3SY85LX6/ppOfP4SbfwZbKfd6DccbLRiB13pwpzbSK0nU52OEJxOqcJ2Uensr6RkrWztWLIq90sNOn1zRAoOAw==.sig.ed25519"
    m2 = Message(
        remote_feed,
        OrderedDict(
            [("type", "about"), ("about", remote_feed.id), ("name", "morpheus"), ("description", "Dude with big jaw")]
        ),
        signature,
        previous=m1,
        timestamp=1495706447426,
    )
    assert m2.timestamp == 1495706447426
    assert m2.previous is m1
    assert m2.sequence == 2
    assert m2.signature == signature
    m2.verify(signature)
    assert m2.key == "%nx13uks5GUwuKJC49PfYGMS/1pgGTtwwdWT7kbVaroM=.sha256"


def test_remote_no_signature(remote_feed: Feed) -> None:  # pylint: disable=redefined-outer-name
    """Test remote feed without a signature"""

    with pytest.raises(ValueError):
        Message(
            remote_feed,
            OrderedDict(
                [("type", "about"), ("about", remote_feed.id), ("name", "neo"), ("description", "The Chosen One")]
            ),
            None,
            timestamp=1495706260190,
        )


def test_serialize(local_feed: LocalFeed) -> None:  # pylint: disable=redefined-outer-name
    """Test feed serialization"""

    m1 = LocalMessage(
        local_feed,
        OrderedDict([("type", "about"), ("about", local_feed.id), ("name", "neo"), ("description", "The Chosen One")]),
        timestamp=1495706260190,
    )

    assert m1.serialize() == SERIALIZED_M1


def test_parse(local_feed: LocalFeed) -> None:  # pylint: disable=redefined-outer-name
    """Test feed parsing"""

    m1 = LocalMessage.parse(SERIALIZED_M1, local_feed)
    assert m1.content == {"type": "about", "about": local_feed.id, "name": "neo", "description": "The Chosen One"}
    assert m1.timestamp == 1495706260190


def test_local_unsigned(local_feed: LocalFeed, mocker: MockerFixture) -> None:  # pylint: disable=redefined-outer-name
    """Test creating an unsigned message on a local feed"""

    mocked_dt = mocker.Mock(spec=datetime)
    mocked_dt.utcnow = mocker.MagicMock(return_value=datetime(2023, 3, 7, 11, 45, 54, 0, tzinfo=timezone.utc))
    mocker.patch("ssb.feed.models.datetime", mocked_dt)

    msg = LocalMessage(local_feed, OrderedDict({"test": True}))

    assert msg.feed == local_feed
    assert msg.content == {"test": True}
    assert msg.sequence == 1
    assert msg.previous is None
    assert msg.timestamp == 1678189554000
    assert msg.signature == (
        "WjkA5rjzsYDHqeavEPcbNAbRMp5NRFDBNATMWgcsccso8sfwhaWnIEvQW79fA5YgKKybzlIsCMWHherToEI2DA==.sig.ed25519"
    )


def test_local_signed(local_feed: LocalFeed) -> None:  # pylint: disable=redefined-outer-name
    """Test creating a signed message on a local feed"""

    msg = LocalMessage(
        local_feed,
        OrderedDict({"test": True}),
        timestamp=1678189554000,
        signature=(
            "WjkA5rjzsYDHqeavEPcbNAbRMp5NRFDBNATMWgcsccso8sfwhaWnIEvQW79fA5YgKKybzlIsCMWHherToEI2DA==.sig.ed25519"
        ),
    )

    assert msg.feed == local_feed
    assert msg.content == {"test": True}
    assert msg.sequence == 1
    assert msg.previous is None
    assert msg.timestamp == 1678189554000
    assert msg.signature == (
        "WjkA5rjzsYDHqeavEPcbNAbRMp5NRFDBNATMWgcsccso8sfwhaWnIEvQW79fA5YgKKybzlIsCMWHherToEI2DA==.sig.ed25519"
    )


@pytest.mark.parametrize(
    "timestamp,expected",
    (
        (datetime(2023, 3, 7, 11, 45, 54, 0, tzinfo=timezone.utc), 1678189554000),
        (datetime(2013, 5, 2, 2, 3, 4, 567890, tzinfo=timezone.utc), 1367460184567),
    ),
)
def test_millis(timestamp: datetime, expected: int, mocker: MockerFixture) -> None:
    """Test the get_millis_1970() function"""

    mocked_dt = mocker.Mock(spec=datetime)
    mocked_dt.utcnow = mocker.MagicMock(return_value=timestamp)
    mocker.patch("ssb.feed.models.datetime", mocked_dt)

    assert get_millis_1970() == expected
