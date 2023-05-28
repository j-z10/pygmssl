from ._gm import _gm


def get_gmssl_version_str() -> str:
    return _gm.gmssl_version_str().decode('utf-8')


def get_gmssl_version_num() -> str:
    return _gm.gmssl_version_num()


VERSION = __version__ = '0.0.3'
