from ctypes import *
from typing import Optional
from ._gm import _gm

SM3_DIGEST_SIZE = 32
SM3_BLOCK_SIZE = 64
SM3_STATE_WORDS = 8
SM3_HMAC_SIZE = SM3_DIGEST_SIZE


class SM3CTX(Structure):
    _fields_ = [
        ('digest', c_uint32 * SM3_STATE_WORDS),
        ('nblocks', c_uint64),
        ('block', c_uint8 * SM3_BLOCK_SIZE),
        ('num', c_size_t),
    ]


class SM3:
    def __init__(self, data: Optional[bytes] = None):
        self._sm3_ctx = SM3CTX()
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
