FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

# Install Build Essentials
RUN apt-get update && \
    apt-get install -y build-essential cmake git

# Install GmSSL
RUN git clone -b 'v3.1.1' --depth 1 https://github.com/guanzhi/GmSSL.git &&\
    cd GmSSL && mkdir build && cd build &&\
    cmake .. && make && make test && make install &&\
    ldconfig

# Install poetry
RUN pip install poetry
