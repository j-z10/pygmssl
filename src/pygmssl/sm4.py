from ctypes import byref, c_uint8, c_size_t, c_uint32, Structure, c_char_p
from enum import Enum

from ._gm import _gm

SM4_KEY_SIZE = 16
SM4_BLOCK_SIZE = 16
SM4_NUM_ROUNDS = 32


class _SM4_KEY(Structure):
    _fields_ = [
        ('rk', c_uint32 * SM4_NUM_ROUNDS)
    ]


class _SM4_CBC_CTX(Structure):
    _fields_ = [
        ('sm4_key', _SM4_KEY),
        ('iv', c_uint8 * SM4_BLOCK_SIZE),
        ('block', c_uint8 * SM4_BLOCK_SIZE),
        ('block_nbytes', c_size_t),
    ]

    def init(self, key: bytes, iv: bytes, encrypt: bool):
        assert len(key) == 16
        assert len(iv) == 16
        if encrypt:
            _gm.sm4_cbc_encrypt_init(byref(self), c_char_p(key), c_char_p(iv))
        else:
            _gm.sm4_cbc_decrypt_init(byref(self), c_char_p(key), c_char_p(iv))
        self._result: list[bytes] = []
        self._encrypt = encrypt

    def encrypt_update(self, data: bytes):
        outbuf = (c_uint8 * 4196)()
        out_length = c_size_t(0)
        inbuf = (c_uint8 * 4096)()
        for i in range(0, len(data), 4096):
            chunk = data[i:i + 4096]
            inbuf[:len(chunk)] = chunk
            _gm.sm4_cbc_encrypt_update(byref(self), byref(inbuf), len(chunk), byref(outbuf), byref(out_length))
            self._result.append(bytes(outbuf[:out_length.value]))

    def decrypt_update(self, encrypted_data: bytes):
        outbuf = (c_uint8 * 4196)()
        out_length = c_size_t(0)
        inbuf = (c_uint8 * 4096)()
        for i in range(0, len(encrypted_data), 4096):
            chunk = encrypted_data[i:i + 4096]
            inbuf[:len(chunk)] = chunk
            _gm.sm4_cbc_decrypt_update(byref(self), byref(inbuf), len(chunk), byref(outbuf), byref(out_length))
            self._result.append(bytes(outbuf[:out_length.value]))

    def encrypt_get(self) -> bytes:
        outbuf = (c_uint8 * 4196)()
        out_length = c_size_t(0)
        _gm.sm4_cbc_encrypt_finish(byref(self), byref(outbuf), byref(out_length))
        self._result.append(bytes(outbuf[:out_length.value]))
        return b''.join(self._result)

    def decrypt_get(self) -> bytes:
        outbuf = (c_uint8 * 4196)()
        out_length = c_size_t(0)
        _gm.sm4_cbc_decrypt_finish(byref(self), byref(outbuf), byref(out_length))
        self._result.append(bytes(outbuf[:out_length.value]))
        return b''.join(self._result)


_MOD_CTX_DICT = {
    'CBC': _SM4_CBC_CTX
}


class MOD(str, Enum):
    CBC = 'CBC'


class SM4:
    def __init__(self, key: bytes, *, mode: MOD, iv: bytes):
        self._ctx = _MOD_CTX_DICT[mode.value.upper()]()
        self.key = key
        self.iv = iv

    def encrypt(self, data: bytes) -> bytes:
        self._ctx.init(self.key, self.iv, encrypt=True)
        self._ctx.encrypt_update(data)
        return self._ctx.encrypt_get()

    def decrypt(self, encrypted_data: bytes) -> bytes:
        self._ctx.init(self.key, self.iv, encrypt=False)
        self._ctx.decrypt_update(encrypted_data)
        return self._ctx.decrypt_get()
