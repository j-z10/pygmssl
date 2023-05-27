from unittest import TestCase
from pygmssl.sm3 import SM3, SM3HMAC

test_pub_key = b'\xe8G\x0be\xc3P\x12\x10\xa9+\xe6n%\x9dc\xe9\xed\xaeBEf\xab\xd0\x12t\x01RQ\xb8\xceJ\xb0\x9b;\x17\xbb.\xf7i\x00\x18Nq~\xa3\xf4n\xf8\xd7\xdd%m-@\xa3\xc3tv\xe4\xe2\xf7\x81\x83\xe0'
test_pri_key = b'\x87\x95\x84V\xcej\x8cq\xd1\x10\x94\xa7\xb7\x8d\xc1\x9a\x98\xcf\xe7\x84\x90\x9d\x8d\xd2\xff\xb4\xaeo2\xb8j\x1b'

class TestSM3(TestCase):
    def test_001_sm3_init(self):
        s = SM3(b'hello, world')
        self.assertEqual(s.hexdigest(), '02df30dff15f2ccb72bffdcb44e68d4d09974036dc7a6927e556fbef421c7f34')

    def test_002_sm3_update(self):
        s = SM3()
        s.update(b'hello,')
        s.update(b' world')
        self.assertEqual(s.hexdigest(), '02df30dff15f2ccb72bffdcb44e68d4d09974036dc7a6927e556fbef421c7f34')

    def test_003_sm3_unicode(self):
        s = SM3(b'hello, ')
        s.update('中国'.encode('utf-8'))
        self.assertEqual(s.hexdigest(), '8800ffdad7b39f09312d61877e33e5814f76b5b2a97cba9f2caeb6117296d9d3')

    def test_004_sm3_hash_with_sm2_default_id(self):
        s = SM3.hash_with_sm2(b'abc', pub_key=test_pub_key)
        self.assertEqual(s.hexdigest(), 'ec6781ebf9fc156ac95dbf4df20688f998a121aea34ee71b727fc8b9195d4b42')

    def test_004_sm3_hash_with_sm2_and_id(self):
        s = SM3.hash_with_sm2(b'abc', pub_key=test_pub_key, id=b'zhangjie')
        self.assertEqual(s.hexdigest(), '4c3d2d21c9414db7837c9c495b30415dd39ee8ff127a47a560c8586df40cbdf5')

    def test_004_sm3_hash_update_with_sm2_and_id(self):
        s = SM3.hash_with_sm2(b'abc', pub_key=test_pub_key, id=b'zhangjie')
        s.update('中国'.encode('utf-8'))
        self.assertEqual(s.hexdigest(), '14e6d70f7b60a849ad9bfea5d0790e2b2c8765e87b2859142f087c67e8bc4e5d')


class TestSM3HMAC(TestCase):
    def test_001_sm3_hmac(self):
        s = SM3HMAC(key=b'123', data=b'hello, world')
        self.assertEqual(s.hexdigest(), '4410e0fef1ae0a641c7c4f1a7f6c7cef5b992f80607d5275f669d8942a77cc08')

    def test_002_sm3_hmac_update(self):
        s = SM3HMAC(b'123')
        s.update(b'hello,')
        s.update(b' world')
        self.assertEqual(s.hexdigest(), '4410e0fef1ae0a641c7c4f1a7f6c7cef5b992f80607d5275f669d8942a77cc08')