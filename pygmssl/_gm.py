import sys
import warnings
from ctypes import cdll, c_char_p
from ctypes.util import find_library

libgm = find_library('gmssl')
if not libgm:
    warnings.warn("gmssl library not found, you should install GmSSL first.\nhttps://github.com/guanzhi/GmSSL")
    sys.exit(1)
else:
    _gm = cdll.LoadLibrary(libgm)
    _gm.gmssl_version_str.restype = c_char_p
