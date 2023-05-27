from unittest import TestCase

from pygmssl.sm2 import SM2

test_pub_key = b'\xe8G\x0be\xc3P\x12\x10\xa9+\xe6n%\x9dc\xe9\xed\xaeBEf\xab\xd0\x12t\x01RQ\xb8\xceJ\xb0\x9b;\x17\xbb.\xf7i\x00\x18Nq~\xa3\xf4n\xf8\xd7\xdd%m-@\xa3\xc3tv\xe4\xe2\xf7\x81\x83\xe0'
test_pri_key = b'\x87\x95\x84V\xcej\x8cq\xd1\x10\x94\xa7\xb7\x8d\xc1\x9a\x98\xcf\xe7\x84\x90\x9d\x8d\xd2\xff\xb4\xaeo2\xb8j\x1b'


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
        self.assertNotEqual(k.pub_key, b'\x00'*64)
        self.assertNotEqual(k.pri_key, b'\x00'*32)

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
