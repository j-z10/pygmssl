# pygmssl
A Python ctypes GmSSL implementation
=======

## 1 INSTALL
### 1.1 install GmSSL
```bash
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL && mkdir build && cd build && cmake ..
make && make test && sudo make install
sudo ldconfig

# check gmssl installed
gmssl version
```

### 1.2 install pygmssl
```bash
python -m pip install pygmssl
```

## 2 Usage
