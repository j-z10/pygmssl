from ctypes import byref, c_uint8, c_size_t, Structure, c_char_p, c_void_p
import tempfile

from Cryptodome.Util.asn1 import DerSequence

from ._gm import _gm, libc
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

    def sign(self, data: bytes, id: bytes = SM2_DEFAULT_ID, asn1: bool = False) -> bytes:
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
        sig = bytes(sigdst[:sigdst_len.value])
        if asn1:
            _k = DerSequence()
            _k.decode(sig)
            r, s = _k[0], _k[1]
            sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return sig

    def verify(self, data: bytes, sig: bytes, id: bytes = SM2_DEFAULT_ID, asn1: bool = False) -> bool:
        if len(sig) == 64:
            if not asn1:
                raise ValueError('when sig is 64 bytes, ans1 flag must be true')
            # asn1 der格式的, 通常是JAVA搞过来的
            _k = DerSequence()
            _k.append(int.from_bytes(sig[:32], 'big'))
            _k.append(int.from_bytes(sig[32:], 'big'))
            sig = _k.encode()
        _verify_ctx = _SM2_SIGN_CTX()
        _gm.sm2_verify_init(byref(_verify_ctx), byref(self._sm2_key), c_char_p(id), len(id))
        buff = (c_uint8 * 4096)()
        for i in range(0, len(data), 4096):
            chunk = data[i:i + 4096]
            buff[:len(chunk)] = chunk
            _gm.sm2_verify_update(byref(_verify_ctx), byref(buff), len(chunk))
        ret = _gm.sm2_verify_finish(byref(_verify_ctx), c_char_p(sig), len(sig))
        return ret == 1

    def encrypt(self, data: bytes) -> bytes:
        if len(data) > SM2_MAX_PLAINTEXT_SIZE:
            raise ValueError('to encrypt data\'s length must <= sm2.SM2_MIN_PLAINTEXT_SIZE')
        buff = (c_uint8 * SM2_MAX_PLAINTEXT_SIZE)()
        buff[:len(data)] = data
        out = (c_uint8 * SM2_MAX_CIPHERTEXT_SIZE)()
        length = c_size_t()
        _gm.sm2_encrypt(byref(self._sm2_key), byref(buff), len(data), byref(out), byref(length))
        return bytes(out[:length.value])

    def decrypt(self, data: bytes) -> bytes:
        if len(data) > SM2_MAX_CIPHERTEXT_SIZE:
            raise ValueError('to decrypt data\'s length must <= sm2.SM2_MAX_CIPHERTEXT_SIZE')
        buff = (c_uint8 * SM2_MAX_CIPHERTEXT_SIZE)()
        buff[:len(data)] = data
        out = (c_uint8 * SM2_MAX_PLAINTEXT_SIZE)()
        length = c_size_t()
        _gm.sm2_decrypt(byref(self._sm2_key), byref(buff), len(data), byref(out), byref(length))
        return bytes(out[:length.value])

    def export_encrypted_private_key_to_pem(self, password: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_f:
            libc.fopen.restype = c_void_p
            fp = libc.fopen(tmp_f.name.encode('utf8'), 'wb')
            assert _gm.sm2_private_key_info_encrypt_to_pem(byref(self._sm2_key), c_char_p(password), c_void_p(fp)) == 1
            libc.fclose(c_void_p(fp))
            with open(tmp_f.name, 'rb') as f:
                res = f.read()
            return res

    def export_public_key_to_pem(self) -> bytes:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_f:
            libc.fopen.restype = c_void_p
            fp = libc.fopen(tmp_f.name.encode('utf8'), 'wb')
            assert _gm.sm2_public_key_info_to_pem(byref(self._sm2_key), c_void_p(fp)) == 1
            libc.fclose(c_void_p(fp))
            with open(tmp_f.name, 'rb') as f:
                res = f.read()
            return res

    @classmethod
    def import_private_from_pem(cls, pem: bytes, password: bytes) -> 'SM2':
        with tempfile.NamedTemporaryFile(delete=False) as tmp_f:
            with open(tmp_f.name, 'wb') as f:
                f.write(pem)
            libc.fopen.restype = c_void_p
            fp = libc.fopen(tmp_f.name.encode('utf8'), 'rb')
            obj = SM2()
            assert _gm.sm2_private_key_info_decrypt_from_pem(byref(obj._sm2_key), c_char_p(password), c_void_p(fp)) == 1
            libc.fclose(c_void_p(fp))
            return obj

    @classmethod
    def import_public_from_pem(cls, pem: bytes) -> 'SM2':
        with tempfile.NamedTemporaryFile(delete=False) as tmp_f:
            with open(tmp_f.name, 'wb') as f:
                f.write(pem)
            libc.fopen.restype = c_void_p
            fp = libc.fopen(tmp_f.name.encode('utf8'), 'rb')
            obj = SM2()
            assert _gm.sm2_public_key_info_from_pem(byref(obj._sm2_key), c_void_p(fp)) == 1
            libc.fclose(c_void_p(fp))
            return obj
