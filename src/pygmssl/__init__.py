from ._gm import _gm
from .sm2 import SM2
from .sm3 import SM3
from .sm4 import SM4


def get_gmssl_version_str() -> str:
    return _gm.gmssl_version_str().decode('utf-8')


def get_gmssl_version_num() -> str:
    return _gm.gmssl_version_num()


VERSION = __version__ = '0.1.0'
__all__ = ['SM2', 'SM3', 'SM4', 'get_gmssl_version_str', 'get_gmssl_version_num', 'VERSION', '__version__']
