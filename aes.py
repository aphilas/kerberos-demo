import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES as CryptoAES


class AES(object):
    """AES Utils

    original_author - https://stackoverflow.com/users/2262117/mnothic
    Modified to make methods static, and to allow methods to pass in key
    """

    block_size = CryptoAES.block_size

    @staticmethod
    def encrypt(raw, key):
        parsed_key = hashlib.sha256(key.encode()).digest()
        raw = AES._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = CryptoAES.new(parsed_key, CryptoAES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    @staticmethod
    def decrypt(enc, key):
        parsed_key = hashlib.sha256(key.encode()).digest()
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        cipher = CryptoAES.new(parsed_key, CryptoAES.MODE_CBC, iv)
        return AES._unpad(cipher.decrypt(enc[AES.block_size :])).decode("utf-8")

    @staticmethod
    def _pad(s):
        block_size = AES.block_size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(
            AES.block_size - len(s) % AES.block_size
        )

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[len(s) - 1 :])]
