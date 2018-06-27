#!/bin/sh

if [ ! -d third_party/openssl ]; then
    git clone https://github.com/openssl/openssl.git third_party/openssl
    cd third_party/openssl
    git checkout f70425d3ac5e4ef17cfa116d99f8f03bbac1c7f2
    ./config && make
    cd ../..
fi

cd bbc_simple/core/libbbcsig
make clean
make

if [ ! -d venv ]; then
    python3 -mvenv venv
fi

source venv/bin/activate
pip install -r requirements.txt
