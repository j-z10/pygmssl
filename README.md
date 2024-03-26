[![codecov](https://codecov.io/gh/j-z10/pygmssl/graph/badge.svg?token=PS29GCO00T)](https://codecov.io/gh/j-z10/pygmssl)
# pygmssl

A Python ctypes [GmSSL](https://github.com/guanzhi/GmSSL)v3.1.1 implementation
=======

## INSTALL
### install GmSSL
```bash
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL && git checkout tags/v3.1.1
mkdir build && cd build && cmake ..
make && make test && sudo make install
sudo ldconfig

# check gmssl installed
gmssl version
```

### install pygmssl
```bash
python -m pip install pygmssl
```

## USAGE

### SM3
```python3
from pygmssl.sm3 import SM3

# sm3 hash all data
data = b'hello, world'
assert SM3(data).hexdigest() == '02df30dff15f2ccb72bffdcb44e68d4d09974036dc7a6927e556fbef421c7f34'

# sm3 hash data by part
s3 = SM3()
for part_data in [b'hel', b'lo', b', world']:
    s3.update(part_data)
assert s3.hexdigest() == '02df30dff15f2ccb72bffdcb44e68d4d09974036dc7a6927e556fbef421c7f34'

# sm3 hash with sm2 public key and id extra
# if not id, id will be sm2 default id, which is b'1234567812345678'
sm2_pub_key = b'\xe8G\x0be\xc3P\x12\x10\xa9+\xe6n%\x9dc\xe9\xed\xaeBEf\xab\xd0\x12t\x01RQ\xb8\xceJ\xb0\x9b;\x17\xbb.\xf7i\x00\x18Nq~\xa3\xf4n\xf8\xd7\xdd%m-@\xa3\xc3tv\xe4\xe2\xf7\x81\x83\xe0'
assert SM3.hash_with_sm2(data, sm2_pub_key).hexdigest() == 'cad9730d3d178bf4c234ab7d2b1fc39569af314faecda258f30ee92456f53d2f'
assert SM3.hash_with_sm2(data, sm2_pub_key, id=b'1234567812345678').hexdigest() == 'cad9730d3d178bf4c234ab7d2b1fc39569af314faecda258f30ee92456f53d2f'
assert SM3.hash_with_sm2(data, sm2_pub_key, id=b'123').hexdigest() == 'd5ba879b0197c1a528283ff9a2b25f347474749b27ab5fd7c8a55648fff1f861'

# sm3 hash with sm2 public key by part
s3 = SM3.hash_with_sm2(b'', sm2_pub_key)
for part_data in [b'hel', b'lo', b', world']:
    s3.update(part_data)
assert s3.hexdigest() == 'cad9730d3d178bf4c234ab7d2b1fc39569af314faecda258f30ee92456f53d2f'
```
### SM3-HMAC

```python3
from pygmssl.sm3 import SM3HMAC

# sm3 hmac all data
data = b'hello, world'
assert SM3HMAC(key=b'123', data=data).hexdigest() == '4410e0fef1ae0a641c7c4f1a7f6c7cef5b992f80607d5275f669d8942a77cc08'

# sm3 hmac data by part
s3 = SM3HMAC(key=b'123')
for part_data in [b'hel', b'lo', b', world']:
    s3.update(part_data)
assert s3.hexdigest() == '4410e0fef1ae0a641c7c4f1a7f6c7cef5b992f80607d5275f669d8942a77cc08'
```

### SM4
```python3
from pygmssl.sm4 import SM4, MOD

# CBC, must 16 bytes key and 16 bytes iv
key = b'F\x7f\x8e7\x05\xc8\x14\x92\xa8P\x8feGx\xf6\xfc'
iv = b'W\xd3,A\x97L\x0e\xfd\xbe\xb5@\xa9\xb0\xe2L\xdf'
cipher = SM4(key, mode=MOD.CBC, iv=iv)
data = b'hello, world'
assert cipher.decrypt(cipher.encrypt(data)) == data

```

### SM2
```python3
from pygmssl.sm2 import SM2

# generate sm2 private key and public key
s2 = SM2.generate_new_pair()
print(s2.pub_key)   # 64 byte public key
print(s2.pri_key)   # 32 byte private key

# 64 byte public_key or 65 byte public key(which is b'\x04' + 64 byte)
test_pub_key = b'\xe8G\x0be\xc3P\x12\x10\xa9+\xe6n%\x9dc\xe9\xed\xaeBEf' \
               b'\xab\xd0\x12t\x01RQ\xb8\xceJ\xb0\x9b;\x17\xbb.\xf7i\x00' \
               b'\x18Nq~\xa3\xf4n\xf8\xd7\xdd%m-@\xa3\xc3tv\xe4\xe2\xf7\x81\x83\xe0'
test_pri_key = b'\x87\x95\x84V\xcej\x8cq\xd1\x10\x94\xa7\xb7\x8d\xc1\x9a' \
               b'\x98\xcf\xe7\x84\x90\x9d\x8d\xd2\xff\xb4\xaeo2\xb8j\x1b'

# SM2 sign and verify with default id
signer = SM2(pub_key=test_pub_key, pri_key=test_pri_key)
data = b'hello, world'
sig = signer.sign(data) # if not id, id will be sm2.SM2_DEFAULT_ID
assert signer.verify(data, sig) == True

# SM2 sign and verify with id
signer2 = SM2(pub_key=test_pub_key, pri_key=test_pri_key)
data = b'hello, world'
sig = signer2.sign(data, id=b'123') # if not id, id will be sm2.SM2_DEFAULT_ID
assert signer2.verify(data, sig, id=b'123') == True
assert signer2.verify(data + b'\x00', sig, id=b'123') == False  # libgmssl will print some fail info

# 如果Java sign可能给出的不是asn1 der格式的sig, 签名和验签的时候指定asn1=True, 将会获取签名后的64位实际数据
zk = SM2(pub_key=test_pub_key, pri_key=test_pri_key)
data = b'hello, world'
sig = zk.sign(data, id=b'123', asn1=True)
assert len(sig) == 64
assert zk.verify(data, sig, id=b'123', asn1=True) == True

# SM2 encrypt and decrypt, data's length <= sm2.SM2_MAX_PLAINTEXT_SIZE
en = SM2(pub_key=test_pub_key)
data = b'hello, world'
s_data = en.encrypt(data)

de = SM2(pri_key=test_pri_key)
d_data = de.decrypt(s_data)
assert d_data == data
```
