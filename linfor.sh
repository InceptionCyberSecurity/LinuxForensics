Last login
$ lastlog
$ last

Users with login shells
$ cat /etc/passwd | grep sh$

List users’ cron
$ for user in $(cat /etc/passwd | cut -f1 -d: ); do echo $user; crontab -u $user -l; done

# users with shells only
$ for user in $(cat /etc/passwd | grep sh$ | cut -f1 -d: ); do echo $user; crontab -u $user -l; done

SSH authorized keys
$ find / -type f -name authorized_keys


Show process tree with username, TTY, and wide output.
$ ps auxfww

Process details
$ lsof -p [pid]

Show all connections don’t resolve names (IP only)
$ lsof -i -n
$ netstat -anp

# Look for tcp only
$ netstat -antp
$ ss -antp

List all services
$ service --status-all

List firewall rules
$ iptables --list-rules

List all timers
$ systemctl list-timers --all

Look to these file to see if the DNS has been poisoned.
/etc/hosts
/etc/resolv.conf


Files and Folders
Show list files and folder with nano timestamp, sort by modification time (newest).
$ ls --full-time -lt

List all files that were modified on a specific date/time.
# List files which were modified on 2021-06-16 (YYYY-MM-DD)
$ find / -newermt "2021-06-16" -ls 2>/dev/null

# List files which were modified on 2021-05-01 until 2021-05-09 (9 days ago)
$ find / -newermt "2021-05-01" ! -newermt "2021-05-10" -ls 2>/dev/null

# List files which were modified on 2021-05-01 until 2021-05-09 (9 days ago) + add filter
$ find / -newermt "2021-05-01" ! -newermt "2021-05-10" -ls 2>/dev/null | grep -v 'filterone\|filtertwo'

# List files modified between 01:00 and 07:00 on June 16 2021.
$ find / -newermt "2021-06-16 01:00:00" ! -newermt "2021-06-16 07:00:00" -ls 2>/dev/null

# List files that were accessed exactly 2 days ago.
$ find / -atime 2 -ls 2>/dev/null

# List files that were modified in the last 2 days.
$ find / -mtime -2 -ls 2>/dev/null

File inspection
$ stat [file]
$ exiftool [file]

Observe changes in files
$ find . -type f -exec md5sum {} \; | awk '{print $1}' | sort | uniq -c | grep ' 1 ' | awk '{print $2	}'

Look for cap_setuid+ep in binary capabilities
$ getcap -r /usr/bin/
$ getcap -r /bin/
$ getcap -r / 2>/dev/null

SUID
$ find / -type f -perm -u=s 2>/dev/null

Log auditing
# 3rd party
$ aureport --tty

Persistence areas
Directories:
/etc/cron*/
/etc/incron.d/*
/etc/init.d/*
/etc/rc*.d/*
/etc/systemd/system/*
/etc/update.d/*
/var/spool/cron/*
/var/spool/incron/*
/var/run/motd.d/*

Files:
/etc/passwd
/etc/sudoers
/home/<user>/.ssh/authorized_keys
/home/<user>/.bashrc

****************************************************************************************************
https://sechive1.wixsite.com/security-hive/post/linux-forensics-the-complete-cheatsheet
PHASE 0 Risk Audit
Password hunting
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;

search for possible Privilege Escalation Paths
wget "https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh" -O linpeas.sh
./linpeas.sh -a #all checks - deeper system enumeration, but it takes longer to complete.
./linpeas.sh -s #superfast & stealth - This will bypass some time consuming checks. In stealth mode Nothing will be written to the disk.
./linpeas.sh -P #Password - Pass a password that will be used with sudo -l and bruteforcing other users

This shell script will show relevant information about the security of the local Linux system, helping to escalate privileges.
wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh
./lse.sh -l1 # shows interesting information that should help you to privesc
./lse.sh -l2 # dump all the information it gathers about the system

PHASE 1 Users and Groups
user List
cat /etc/passwd

user creation
passwd -S [USER_NAME]

UID users
grep :0: /etc/passwd

temp users
find / -nouser -print

Groups
cat /etc/group
cat /etc/sudoers

PHASE 2 system Config
network
cat /etc/network/interfaces
cat /etc/resolve.conf
cat /etc/dnsmasq.conf

OS
cat /etc/os-release

hostnAME
cat /etc/hostname

TIMEZONE
cat /etc/timezone


phase 3 uSERS aCTIVITIES

RECENT ACCESS
find . -type f -atime -7 -printf “%AY%Am%Ad%AH%AM%AS %h/%s/%f\n” -user |sort -n
find . -type f -mtime -7 -printf “%TY%Tm%Td%TH%TM%TS %h — %s — %f\n” -user |sort -n
find . -type f -ctime -7 -printf “%CY%Cm%Cd%CH%CM%CS %h — %s — %f\n” -user |sort -n

basH HISTORY
cat .bash_history
cat .bashrc

mOUNT pOINTS
cat /proc/mounts


PHASE 4 Log Analysis

Log entries
lastlog

Auth.Log
cat /var/log/auth.log

Deamon.log
cat var/log/deamon.log

SysLog
cat var/log/syslog

WTMP
cat /var/log/btmp

Appication Logs ????
 Some of those logs to name are apache2, httpd, samba, MySQL etc.


PHASE 5 Persistance

Services
services –status-all

Processes
top
ps aux
lsof -p [pid]

Scheduled Jobs
cat /etc/crontab

DNS Resolves
cat /etc/resolve.conf

Firewall Rules
cat /etc/resolve.conf

Network Connections
netstat -nap

IMAGE TOOLS
fmem

Memoery
Lime (http://code.google.com/p/lime-forensics/)
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
