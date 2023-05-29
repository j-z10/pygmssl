import os
from unittest import TestCase

from pygmssl.sm4 import SM4, MOD


class TestSM4(TestCase):
    def setUp(self) -> None:
        self._16_key = b"\x97\xfc\xa3\xd7\t;\xf3\xd1'\x9c\x8c\x03\x92\x1c\xf5\xd2"
        self._16_iv = b'p\xce\xb9\x8d\t$x\x9c\x0f]\xea\x92\xae\xa1\x96\x9d'
        self._48_key = b'q\xb4j\xdem\x84|J\xf2\x92u\x14\x8f\x95\x85\x1e\x8fT\x01A' \
                       b'\x19<\xe1\x82t\xf4\x921\x0b\xbb\x9f\xabY8\xf4\xb2\xf2^\x10|\xbf\xf90\xeb\x19\x12,\xd4'

    def test_000_valid_mod(self):
        with self.assertRaises(ValueError):
            SM4(self._16_key, mode=MOD('CDC'), iv=b'123')

    def test_001_cbc_encrypt(self):
        k = SM4(self._16_key, mode=MOD.CBC, iv=self._16_iv)
        k2 = SM4(self._16_key, mode=MOD.CBC, iv=self._16_iv)
        e_data = k.encrypt(b'hello, world')
        self.assertEqual(b'W\x855 su+\x95\xd9@\x0fGL\xacKk', e_data)
        self.assertEqual(b'hello, world', k2.decrypt(e_data))

    def test_002_cbc_bulk_encrypt(self):
        k = SM4(self._16_key, mode=MOD.CBC, iv=self._16_iv)
        k2 = SM4(self._16_key, mode=MOD.CBC, iv=self._16_iv)
        bulk_data = os.urandom(512) * 2099
        self.assertEqual(bulk_data, k2.decrypt(k.encrypt(bulk_data)))
