import json
import os
from typing import Any, Callable
from base64 import b64encode
import datetime as dt
from aes import AES
import dataclasses
from dataclasses import dataclass


class JSONEncoder(json.JSONEncoder):
    """Custome JSONEncoder to encode dataclasses as dicts"""

    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)

        return super().default(o)


def random_key() -> str:
    return b64encode(os.urandom(16)).decode("utf-8")


def encode(value) -> str:
    return json.dumps(value, cls=JSONEncoder)


def decode(value) -> Any:
    return json.loads(value)


def serialize_encrypt(value: Any, key: str) -> str:
    """Serializes and encrypts a value

    Args:
        value (Any): Value to encrypt and serialize
        key (str): AES key

    Returns:
        str: Encrypted and serialized output
    """
    return AES.encrypt(encode(value), key)


def deserialize_decrypt(value: Any, key: str, dc: dataclass = None) -> Any:
    """Deserealizes an encrypted value

    Args:
        value (Any): Value to decrypt
        key (str): AES key
        dc (dataclass): Dataclass to initialize dict with

    Returns:
        Any: Decrypted value
    """

    parsed = decode(AES.decrypt(value, key))

    if dataclasses.is_dataclass(dc) and isinstance(parsed, dict):
        return dc(**parsed)

    return parsed


def lt_now(value: (dt.datetime | str)) -> bool:
    """Returns true is datetime or timestamp is in the past

    Args:
        value (datetime|str): datetime or isoformat datetime string

    Returns:
        bool
    """
    then = value

    if isinstance(value, str):
        then = dt.datetime.fromisoformat(value)

    return dt.datetime.now() > then


def transform_dict(object: dict, key: str, predicate: Callable) -> dict:
    """Returns a new dict, with the value of <key> transformed

    Args:
        object (dict): Input dict
        key (str): Key of value to transform
        predicate (Callable): Function to transform value, called with value as first argument

    Returns:
        dict: Output dict
    """
    current = object.get(key)
    clone = dict(object)

    if current:
        clone[key] = predicate(current)

    return clone
