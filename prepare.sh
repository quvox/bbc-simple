#!/bin/sh

if [ ! -d libs/openssl ]; then
    git clone https://github.com/openssl/openssl.git libs/openssl
    pushd libs/openssl
    git checkout f70425d3ac5e4ef17cfa116d99f8f03bbac1c7f2
    ./config && make
    popd
fi

pushd libs/libbbcsig
make clean
make
popd

if [ ! -d venv ]; then
    python3 -mvenv venv
fi
source venv/bin/activate

pip install -r requirements.txt
