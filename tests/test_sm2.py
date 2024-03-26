from unittest import TestCase

from pygmssl.sm2 import SM2

test_pub_key = b'\xe8G\x0be\xc3P\x12\x10\xa9+\xe6n%\x9dc\xe9\xed\xaeBEf' \
               b'\xab\xd0\x12t\x01RQ\xb8\xceJ\xb0\x9b;\x17\xbb.\xf7i\x00' \
               b'\x18Nq~\xa3\xf4n\xf8\xd7\xdd%m-@\xa3\xc3tv\xe4\xe2\xf7\x81\x83\xe0'
test_pri_key = b'\x87\x95\x84V\xcej\x8cq\xd1\x10\x94\xa7\xb7\x8d\xc1\x9a' \
               b'\x98\xcf\xe7\x84\x90\x9d\x8d\xd2\xff\xb4\xaeo2\xb8j\x1b'


class TestSM2(TestCase):
    def setUp(self) -> None:
        self.k = SM2(test_pub_key, test_pri_key)

    def test_001_base(self):
        k = SM2(test_pub_key, test_pri_key)
        self.assertEqual(k.pub_key, test_pub_key)
        self.assertEqual(k.pri_key, test_pri_key)

    def test_002_pub_key(self):
        k2 = SM2(b'\x04' + test_pub_key, test_pri_key)
        self.assertEqual(k2.pub_key, test_pub_key)
        self.assertEqual(k2.pri_key, test_pri_key)

    def test_003_wrong_key(self):
        with self.assertRaises(ValueError):
            SM2(test_pub_key + b'\x03')

        with self.assertRaises(ValueError):
            SM2(pri_key=test_pri_key + b'\x03')

    def test_004_generate_key(self):
        k = SM2.generate_new_pair()
        self.assertEqual(len(k.pub_key), 64)
        self.assertEqual(len(k.pri_key), 32)
        self.assertNotEqual(k.pub_key, b'\x00' * 64)
        self.assertNotEqual(k.pri_key, b'\x00' * 32)

    def test_005_sm2_sign(self):
        data = b'hello, world'
        sig = self.k.sign(data)
        self.assertFalse(self.k.verify(data + b'\x00', sig))
        self.assertTrue(self.k.verify(data, sig))

    def test_006_sm2_sign_with_id(self):
        data = b'hello, world'
        sig = self.k.sign(data, id=b'123')
        self.assertFalse(self.k.verify(data, sig))
        self.assertTrue(self.k.verify(data, sig=sig, id=b'123'))
        self.assertFalse(self.k.verify(b'\x00' + data, sig=sig, id=b'123'))

    def test_007_sm2_encrypt_and_decrypt(self):
        data = b'hello, world'
        self.assertEqual(self.k.decrypt(self.k.encrypt(data)), data)

    def test_008_sm2_encrypt_and_decrypt_check(self):
        data = b'1' * 1024
        with self.assertRaises(ValueError):
            self.k.encrypt(data)
        with self.assertRaises(ValueError):
            self.k.decrypt(data)

    def test_009_sm2_sign_with_asn1(self):
        data = b'hello, world'
        sig = self.k.sign(data, asn1=True)
        self.assertFalse(self.k.verify(data + b'\x00', sig, asn1=True))
        self.assertTrue(self.k.verify(data, sig, asn1=True))

    def test_010_sm2_sign_with_id_asn1(self):
        data = b'hello, world'
        sig = self.k.sign(data, id=b'test', asn1=True)
        self.assertFalse(self.k.verify(data + b'\x00', sig, id=b'test', asn1=True))
        self.assertTrue(self.k.verify(data, sig, id=b'test', asn1=True))

    def test_private_pem_export_and_import(self):
        password = b'test-123-456'
        obj = SM2.generate_new_pair()
        assert obj.pub_key != b'\x00' * 64
        assert obj.pri_key != b'\x00' * 32
        new_obj = SM2.import_private_from_pem(obj.export_encrypted_private_key_to_pem(password), password)
        assert new_obj.pri_key != b'\x00' * 32
        assert new_obj.pri_key == obj.pri_key

        assert new_obj.pub_key != b'\x00' * 64
        assert new_obj.pub_key == obj.pub_key

    def test_pub_pem_export_and_import(self):
        obj = SM2.generate_new_pair()
        assert obj.pub_key != b'\x00' * 64
        assert obj.pri_key != b'\x00' * 32
        new_obj = SM2.import_public_from_pem(obj.export_public_key_to_pem())
        assert new_obj.pri_key == b'\x00' * 32
        assert new_obj.pub_key != b'\x00' * 64
        assert new_obj.pub_key == obj.pub_key
