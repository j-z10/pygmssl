#!/bin/bash
git clone -b 'v3.1.1' --depth 1 https://github.com/guanzhi/GmSSL.git
cd GmSSL && mkdir build && cd build && cmake ..
make && make test && sudo make install
sudo ldconfig

# check gmssl installed
gmssl version