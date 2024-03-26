#!/bin/bash
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL && mkdir build && cd build && cmake ..
make && make test && sudo make install
sudo ldconfig

# check gmssl installed
gmssl version