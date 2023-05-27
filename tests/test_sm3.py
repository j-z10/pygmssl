from unittest import TestCase
from pygmssl.sm3 import SM3

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
