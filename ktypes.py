"""Contains types used in the Kerberos implementation"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Event(str, Enum):
    """
    Hack for easy json.load and json.dump
    Probably avoid "DEBUG", "INFO" and "LOG" fields
    Use string enum values only
    """

    AUTHN = "AUTHN"
    AUTHZ = "AUTHZ"
    DEFAULT = "DEFAULT"
    REPLY_AUTHN = "REPLY_AUTHN"
    REPLY_AUTHZ = "REPLY_AUTHZ"
    REPLY_REQUEST = "REPLY_REQUEST"
    REQUEST = "REQUEST"


@dataclass
class Message:
    source: str
    body: Any
    event: Event = Event.DEFAULT


@dataclass
class Ticket:
    session_key: str
    expiry: str


@dataclass
class ClientTicket(Ticket):
    pass


@dataclass
class TGT(Ticket):
    name: str


@dataclass
class ServerTicket(Ticket):
    name: str


@dataclass
class Authenticator:
    name: str
    expiry: str
