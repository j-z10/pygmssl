from ctypes import *

from ._gm import _gm

SM2_DEFAULT_ID = b'1234567812345678'

class _SM2_POINT(Structure):
    _fields_ = [
        ('x', c_uint8 * 32),
        ('y', c_uint8 * 32),
    ]


class _SM2_KEY(Structure):
    _fields_ = [
        ('pub', _SM2_POINT),
        ('pri', c_uint8 * 32),
    ]


class SM2:
    def __init__(self, pub_key: bytes | None = None, pri_key: bytes | None = None):
        self._sm2_key = _SM2_KEY()
        if pub_key and len(pub_key) == 65 and pub_key[0] == 4:
            # if 65 bytes, 0x04 + pub.x + pub.y
            pub_key = pub_key[1:]
        if pub_key:
            if len(pub_key) != 64:
                raise ValueError('the length of sm2 public key should be 64 bytes')
            self._sm2_key.pub.x[:32] = pub_key[:32]
            self._sm2_key.pub.y[:32] = pub_key[32:64]
        if pri_key:
            if len(pri_key) != 32:
                raise ValueError('the length of sm2 private key should be 32 bytes')
            self._sm2_key.pri[:32] = pri_key

    @classmethod
    def generate_new_pair(cls) -> 'SM2':
        obj = cls()
        _gm.sm2_key_generate(byref(obj._sm2_key))
        return obj

    @property
    def pub_key(self) -> bytes:
        return bytes(self._sm2_key.pub)

    @property
    def pri_key(self) -> bytes:
        return bytes(self._sm2_key.pri)

    def compute_z(self, id:bytes=SM2_DEFAULT_ID) -> bytes:
        z = (c_uint8 * 32)()
        _gm.sm2_compute_z(byref(z), byref(self._sm2_key.pub), c_char_p(id), len(id))
        return bytes(z)