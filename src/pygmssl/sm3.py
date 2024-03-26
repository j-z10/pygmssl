from ctypes import byref, c_uint8, c_size_t, c_uint32, c_uint64, Structure, c_char_p
from typing import Optional

from ._gm import _gm

SM3_DIGEST_SIZE = 32
SM3_BLOCK_SIZE = 64
SM3_STATE_WORDS = 8
SM3_HMAC_SIZE = SM3_DIGEST_SIZE


class _SM3CTX(Structure):
    _fields_ = [
        ('digest', c_uint32 * SM3_STATE_WORDS),
        ('nblocks', c_uint64),
        ('block', c_uint8 * SM3_BLOCK_SIZE),
        ('num', c_size_t),
    ]


class SM3:
    def __init__(self, data: Optional[bytes] = None):
        self._sm3_ctx = _SM3CTX()
        _gm.sm3_init(byref(self._sm3_ctx))
        if data is not None:
            self.update(data)

    def update(self, data: bytes):
        buff = (c_uint8 * 4096)()
        for i in range(0, len(data), 4096):
            chunk = data[i:i + 4096]
            buff[:len(chunk)] = chunk
            _gm.sm3_update(byref(self._sm3_ctx), byref(buff), len(chunk))

    def digest(self) -> bytes:
        dst = (c_uint8 * 32)()
        _gm.sm3_finish(byref(self._sm3_ctx), byref(dst))
        return bytes(dst)

    def hexdigest(self) -> str:
        return self.digest().hex()

    @classmethod
    def hash_with_sm2(cls, data: bytes, pub_key: bytes, id: bytes | None = None) -> 'SM3':
        from .sm2 import SM2
        sm2 = SM2(pub_key=pub_key)
        z = sm2.compute_z(id=id) if id else sm2.compute_z()
        s3 = SM3(z)
        s3.update(data)
        return s3


class _SM3HMACCTX(Structure):
    _fields_ = [
        ('sm3ctx', _SM3CTX),
        ('key', c_uint8 * SM3_BLOCK_SIZE),
    ]


class SM3HMAC:
    def __init__(self, key: bytes, data: bytes | None = None):
        self._ctx = _SM3HMACCTX()
        _gm.sm3_hmac_init(byref(self._ctx), c_char_p(key), len(key))
        if data:
            self.update(data)

    def update(self, data: bytes):
        buff = (c_uint8 * 4096)()
        for i in range(0, len(data), 4096):
            chunk = data[i:i + 4096]
            buff[:len(chunk)] = chunk
            _gm.sm3_hmac_update(byref(self._ctx), byref(buff), len(chunk))

    def digest(self) -> bytes:
        dst = (c_uint8 * 32)()
        _gm.sm3_hmac_finish(byref(self._ctx), byref(dst))
        return bytes(dst)

    def hexdigest(self) -> str:
        return self.digest().hex()
