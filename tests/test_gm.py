from pygmssl import get_gmssl_version_num, get_gmssl_version_str
from unittest import TestCase


class TestSM2(TestCase):
    def test_get_gmssl_version_str(self):
        assert get_gmssl_version_str()

    def test_get_gmssl_version_num(self):
        assert get_gmssl_version_num() > 0
