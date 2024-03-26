import sys
import warnings
from ctypes import cdll, c_char_p
from ctypes.util import find_library

if sys.platform == 'win32':  # pragma: no cover
    libc = cdll.LoadLibrary(find_library('msvcrt'))
else:
    libc = cdll.LoadLibrary(find_library('c'))

libgm = find_library('gmssl')

if not libgm:  # pragma: no cover
    warnings.warn("gmssl library not found, you should install GmSSL first.\n"
                  "https://github.com/guanzhi/GmSSL")
    sys.exit(1)
else:
    _gm = cdll.LoadLibrary(libgm)
    _gm.gmssl_version_str.restype = c_char_p
