from ctypes import cdll, c_char_p
from ctypes.util import find_library

libgm = find_library('gmssl')
_gm = cdll.LoadLibrary(libgm)
_gm.gmssl_version_str.restype = c_char_p


def get_gmssl_version_str() -> str:
    return _gm.gmssl_version_str().decode('utf-8')


def get_gmssl_version_num() -> str:
    return _gm.gmssl_version_num()
