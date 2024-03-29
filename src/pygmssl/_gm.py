import sys
import warnings
from ctypes import cdll, c_char_p, c_void_p, c_int
from ctypes.util import find_library

if sys.platform == 'win32':  # pragma: no cover
    libc = cdll.LoadLibrary(find_library('msvcrt'))
    win32 = True
else:
    libc = cdll.LoadLibrary(find_library('c'))
    win32 = False

libc.fopen.argtypes = [c_char_p, c_char_p]
libc.fopen.restype = c_void_p
libc.fclose.argtypes = [c_void_p]
libc.fclose.restype = c_int


libgm = find_library('gmssl')

if not libgm:  # pragma: no cover
    warnings.warn("gmssl library not found, you should install GmSSL first.\n"
                  "https://github.com/guanzhi/GmSSL")
    sys.exit(1)
else:
    _gm = cdll.LoadLibrary(libgm)
    _gm.gmssl_version_str.restype = c_char_p
    _gm.sm2_private_key_info_encrypt_to_pem.argtypes = [c_void_p, c_char_p, c_void_p]
    _gm.sm2_private_key_info_encrypt_to_pem.restype = c_int
    _gm.sm2_private_key_info_decrypt_from_pem.argtypes = [c_void_p, c_char_p, c_void_p]
    _gm.sm2_private_key_info_decrypt_from_pem.restype = c_int
    _gm.sm2_public_key_info_from_pem.argtypes = [c_void_p, c_void_p]
    _gm.sm2_public_key_info_from_pem.restype = c_int
    _gm.sm2_public_key_info_to_pem.argtypes = [c_void_p, c_void_p]
    _gm.sm2_public_key_info_to_pem.restype = c_int
