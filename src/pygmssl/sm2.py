import base64
from ctypes import byref, c_uint8, c_size_t, Structure, c_char_p, pointer
import functools
import tempfile
import os
from typing import Callable, Literal, Concatenate, Self

from Cryptodome.Util.asn1 import DerSequence

from ._gm import _gm, libc, win32
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
        self._has_pub = self._has_pri = False
        if pub_key and len(pub_key) == 65 and pub_key[0] == 4:
            # if 65 bytes, 0x04 + pub.x + pub.y
            pub_key = pub_key[1:]
        if pub_key:
            self.set_pub(pub_key)
        if pri_key:
            self.set_pri(pri_key)

    def set_pub(self, pub_key: bytes):
        if len(pub_key) != 64:
            raise ValueError('the length of sm2 public key should be 64 bytes')
        self._sm2_key.pub.x[:32] = pub_key[:32]
        self._sm2_key.pub.y[:32] = pub_key[32:64]
        self._has_pub = True

    def set_pri(self, pri_key: bytes):
        if len(pri_key) != 32:
            raise ValueError('the length of sm2 private key should be 32 bytes')
        self._sm2_key.pri[:32] = pri_key
        self._has_pri = True

    @staticmethod
    def check(propery: Literal['_has_pri'] | Literal['_has_pub']):
        def _func[**P, R](fn: Callable[Concatenate[Self, P], R]):
            @functools.wraps(fn)
            def wrapper(self: Self, *args: P.args, **kwargs: P.kwargs) -> R:
                if not getattr(self, propery):
                    raise ValueError(f'{propery} not set')
                return fn(self, *args, **kwargs)
            return wrapper
        return _func

    @classmethod
    def generate_new_pair(cls) -> 'SM2':
        obj = cls()
        _gm.sm2_key_generate(byref(obj._sm2_key))
        obj._has_pri = obj._has_pub = True
        return obj

    @property
    @check('_has_pub')
    def pub_key(self: 'SM2') -> bytes:
        return bytes(self._sm2_key.pub)

    @property
    @check('_has_pri')
    def pri_key(self) -> bytes:
        return bytes(self._sm2_key.pri)

    @check('_has_pub')
    def compute_z(self, id: bytes = SM2_DEFAULT_ID) -> bytes:
        z = (c_uint8 * 32)()
        _gm.sm2_compute_z(byref(z), byref(self._sm2_key.pub), c_char_p(id), len(id))
        return bytes(z)

    @check('_has_pri')
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
            sig = bytes(_k[0].to_bytes(32, 'big') + _k[1].to_bytes(32, 'big'))  # type: ignore
        return sig

    @check('_has_pub')
    def verify(self, data: bytes, sig: bytes, id: bytes = SM2_DEFAULT_ID, asn1: bool = False) -> bool:
        if len(sig) == 64:
            if not asn1:
                raise ValueError('when sig is 64 bytes, ans1 flag must be true')
            # asn1 der格式的, 通常是JAVA搞过来的
            _k = DerSequence()
            _k.append(int.from_bytes(sig[:32], 'big'))  # type: ignore
            _k.append(int.from_bytes(sig[32:], 'big'))  # type: ignore
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

    @check('_has_pub')
    def encrypt(self, data: bytes) -> bytes:
        if len(data) > SM2_MAX_PLAINTEXT_SIZE:
            raise ValueError('to encrypt data\'s length must <= sm2.SM2_MIN_PLAINTEXT_SIZE')
        buff = (c_uint8 * SM2_MAX_PLAINTEXT_SIZE)()
        buff[:len(data)] = data
        out = (c_uint8 * SM2_MAX_CIPHERTEXT_SIZE)()
        length = c_size_t()
        _gm.sm2_encrypt(byref(self._sm2_key), byref(buff), len(data), byref(out), byref(length))
        return bytes(out[:length.value])

    @check('_has_pri')
    def decrypt(self, data: bytes) -> bytes:
        if len(data) > SM2_MAX_CIPHERTEXT_SIZE:
            raise ValueError('to decrypt data\'s length must <= sm2.SM2_MAX_CIPHERTEXT_SIZE')
        buff = (c_uint8 * SM2_MAX_CIPHERTEXT_SIZE)()
        buff[:len(data)] = data
        out = (c_uint8 * SM2_MAX_PLAINTEXT_SIZE)()
        length = c_size_t()
        _gm.sm2_decrypt(byref(self._sm2_key), byref(buff), len(data), byref(out), byref(length))
        return bytes(out[:length.value])

    def _export_encrypted_pri_to_der(self, password: bytes) -> bytes:
        buff = (c_uint8 * 4096)()
        length = c_size_t()
        _gm.sm2_private_key_info_encrypt_to_der(byref(self._sm2_key), password, byref(pointer(buff)), byref(length))
        return bytes(buff[:length.value])

    def _export_pub_to_der(self) -> bytes:
        buff = (c_uint8 * 4096)()
        length = c_size_t()
        _gm.sm2_public_key_info_to_der(byref(self._sm2_key), byref(pointer(buff)), byref(length))
        return bytes(buff[:length.value])

    def _nix_export_private_key_to_encrypted_pem(self, password: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(delete=False) as _tmp_f:
            tmp_f_name = _tmp_f.name
            fp = libc.fopen(tmp_f_name.encode('utf8'), b'wb')

            assert _gm.sm2_private_key_info_encrypt_to_pem(byref(self._sm2_key), c_char_p(password), fp) == 1
            libc.fclose(fp)
            with open(tmp_f_name, 'rb') as f:
                res = f.read()
            return res

    def _win_export_private_key_to_encrypted_pem(self, password: bytes) -> bytes:
        der = self._export_encrypted_pri_to_der(password)
        return self._pem_write(der, 'ENCRYPTED PRIVATE KEY')

    def _nix_export_public_key_to_pem(self) -> bytes:
        with tempfile.NamedTemporaryFile(delete=False) as _tmp_f:
            tmp_f_name = _tmp_f.name
            fp = libc.fopen(tmp_f_name.encode('utf8'), b'wb')
            assert _gm.sm2_public_key_info_to_pem(byref(self._sm2_key), fp) == 1
            libc.fclose(fp)
            with open(tmp_f_name, 'rb') as f:
                res = f.read()
            return res

    def _win_export_public_key_to_pem(self) -> bytes:
        pub_der = self._export_pub_to_der()
        return self._pem_write(pub_der, 'PUBLIC KEY')

    def _pem_write(self, der: bytes, name: str) -> bytes:
        data = base64.b64encode(der).decode('utf8')
        prefix = f'-----BEGIN {name}-----'
        suffix = f'-----END {name}-----'
        tmp: list[str] = [prefix]
        for i in range(0, len(data), 64):
            chunk = data[i:i + 64]
            tmp.append(chunk)
        tmp.append(suffix)
        return ''.join(_line + os.linesep for _line in tmp).encode('utf8')

    @classmethod
    def _nix_import_private_key_from_encrypted_pem(cls, pem: bytes, password: bytes) -> 'SM2':
        with tempfile.NamedTemporaryFile(delete=False) as _tmp_f:
            tmp_f_name = _tmp_f.name
            with open(tmp_f_name, 'wb') as f:
                f.write(pem)
            fp = libc.fopen(tmp_f_name.encode('utf8'), b'rb')
            obj = SM2()
            assert _gm.sm2_private_key_info_decrypt_from_pem(byref(obj._sm2_key), c_char_p(password), fp) == 1
            libc.fclose(fp)
            obj._has_pri = obj._has_pub = True
            return obj

    @classmethod
    def _nix_import_public_key_from_pem(cls, pem: bytes) -> 'SM2':
        with tempfile.NamedTemporaryFile(delete=False) as _tmp_f:
            tmp_f_name = _tmp_f.name
            with open(tmp_f_name, 'wb') as f:
                f.write(pem)
            fp = libc.fopen(tmp_f_name.encode('utf8'), b'rb')
            obj = SM2()
            assert _gm.sm2_public_key_info_from_pem(byref(obj._sm2_key), fp) == 1
            libc.fclose(fp)
            obj._has_pub = True
            return obj

    @staticmethod
    def _pem_read(pem: str, name: str) -> bytes:
        tmp = pem.splitlines()
        prefix = f'-----BEGIN {name}-----'
        suffix = f'-----END {name}-----'
        assert tmp[0] == prefix
        assert tmp[-1] == suffix
        mid = ''.join(tmp[1:-1])
        return base64.b64decode((mid + ('=' * (-len(mid) % 4))).encode())

    @classmethod
    def _win_import_private_key_from_encrypted_pem(cls, pem: bytes, password: bytes) -> 'SM2':
        der_data = cls._pem_read(pem.decode('utf8'), 'ENCRYPTED PRIVATE KEY')
        obj = SM2()
        attr = (c_uint8 * 4096)()
        attr_len = c_size_t()
        p = pointer(attr)
        buf = (c_uint8 * 4096)()
        buf[:len(der_data)] = der_data
        buflen = c_size_t(len(der_data))
        cp = pointer(buf)
        assert _gm.sm2_private_key_info_decrypt_from_der(byref(obj._sm2_key), byref(
            p), byref(attr_len), password, byref(cp), byref(buflen)) == 1
        assert buflen.value == 0
        obj._has_pri = obj._has_pub = True
        return obj

    @classmethod
    def _win_import_public_key_from_pem(cls, pem: bytes) -> 'SM2':
        der_data = cls._pem_read(pem.decode('utf8'), 'PUBLIC KEY')
        obj = SM2()
        buf = (c_uint8 * 4096)()
        buf[:len(der_data)] = der_data
        vlen = c_size_t(len(der_data))
        cp = pointer(buf)
        assert _gm.sm2_public_key_info_from_der(byref(obj._sm2_key), byref(cp), byref(vlen)) == 1
        assert vlen.value == 0
        obj._has_pub = True
        return obj

    if win32:
        export_public_key_to_pem = _win_export_public_key_to_pem
        export_private_key_to_encrypted_pem = _win_export_private_key_to_encrypted_pem
        import_public_key_from_pem = _win_import_public_key_from_pem
        import_private_key_from_encrypted_pem = _win_import_private_key_from_encrypted_pem
    else:
        export_public_key_to_pem = _nix_export_public_key_to_pem
        export_private_key_to_encrypted_pem = _nix_export_private_key_to_encrypted_pem
        import_public_key_from_pem = _nix_import_public_key_from_pem
        import_private_key_from_encrypted_pem = _nix_import_private_key_from_encrypted_pem
