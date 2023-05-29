from ctypes import byref, c_uint8, c_size_t, Structure, c_char_p

from ._gm import _gm
from .sm3 import _SM3CTX

SM2_DEFAULT_ID = b'1234567812345678'
SM2_MIN_SIGNATURE_SIZE = 8
SM2_MAX_SIGNATURE_SIZE = 72
SM2_MIN_PLAINTEXT_SIZE = 1
SM2_MAX_PLAINTEXT_SIZE = 255
SM2_MIN_CIPHERTEXT_SIZE = 45
SM2_MAX_CIPHERTEXT_SIZE = 366


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


class _SM2_SIGN_CTX(Structure):
    _fields_ = [
        ('sm3_ctx', _SM3CTX),
        ('key', _SM2_KEY)
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

    def compute_z(self, id: bytes = SM2_DEFAULT_ID) -> bytes:
        z = (c_uint8 * 32)()
        _gm.sm2_compute_z(byref(z), byref(self._sm2_key.pub), c_char_p(id), len(id))
        return bytes(z)

    def sign(self, data: bytes, id: bytes = SM2_DEFAULT_ID) -> bytes:
        _sign_ctx = _SM2_SIGN_CTX()
        _gm.sm2_sign_init(byref(_sign_ctx), byref(self._sm2_key), c_char_p(id), len(id))
        buff = (c_uint8 * 4096)()
        for i in range(0, len(data), 4096):
            chunk = data[i:i + 4096]
            buff[:len(chunk)] = chunk
            _gm.sm2_sign_update(byref(_sign_ctx), byref(buff), len(chunk))
        sigdst = (c_uint8 * SM2_MAX_SIGNATURE_SIZE)()
        sigdst_len = c_size_t()
        _gm.sm2_sign_finish(byref(_sign_ctx), byref(sigdst), byref(sigdst_len))
        return bytes(sigdst[:sigdst_len.value])

    def verify(self, data: bytes, sig: bytes, id: bytes = SM2_DEFAULT_ID) -> bool:
        _verify_ctx = _SM2_SIGN_CTX()
        _gm.sm2_verify_init(byref(_verify_ctx), byref(self._sm2_key), c_char_p(id), len(id))
        buff = (c_uint8 * 4096)()
        for i in range(0, len(data), 4096):
            chunk = data[i:i + 4096]
            buff[:len(chunk)] = chunk
            _gm.sm2_verify_update(byref(_verify_ctx), byref(buff), len(chunk))
        ret = _gm.sm2_verify_finish(byref(_verify_ctx), c_char_p(sig), len(sig))
        return ret == 1

    def encrypt(self, data:bytes) -> bytes:
        if len(data) > SM2_MAX_PLAINTEXT_SIZE:
            raise ValueError('to encrypt data\'s length must <= sm2.SM2_MIN_PLAINTEXT_SIZE')
        buff = (c_uint8 * SM2_MAX_PLAINTEXT_SIZE)()
        buff[:len(data)] = data
        out = (c_uint8 * SM2_MAX_CIPHERTEXT_SIZE)()
        length = c_size_t()
        _gm.sm2_encrypt(byref(self._sm2_key), byref(buff), len(data), byref(out), byref(length))
        return bytes(out[:length.value])

    def decrypt(self, data:bytes) -> bytes:
        if len(data) > SM2_MAX_CIPHERTEXT_SIZE:
            raise ValueError('to decrypt data\'s length must <= sm2.SM2_MAX_CIPHERTEXT_SIZE')
        buff = (c_uint8 * SM2_MAX_CIPHERTEXT_SIZE)()
        buff[:len(data)] = data
        out = (c_uint8 * SM2_MAX_PLAINTEXT_SIZE)()
        length = c_size_t()
        _gm.sm2_decrypt(byref(self._sm2_key), byref(buff), len(data), byref(out), byref(length))
        return bytes(out[:length.value])
